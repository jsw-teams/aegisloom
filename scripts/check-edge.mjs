import { createContext, SourceTextModule } from "node:vm";
import { parse } from "acorn";
import { build } from "esbuild";

function checkAst(node) {
  if (!node || typeof node !== "object") return;
  if (
    (node.type === "CallExpression" || node.type === "NewExpression") &&
    node.callee?.type === "Identifier" &&
    ["eval", "Function"].includes(node.callee.name)
  )
    throw new Error("Dynamic code evaluation found");
  if (
    (node.type === "ImportDeclaration" || node.type === "ExportNamedDeclaration") &&
    node.source?.value.startsWith("node:")
  )
    throw new Error("Node import found");
  for (const value of Object.values(node))
    if (Array.isArray(value)) {
      for (const child of value) checkAst(child);
    } else if (value && typeof value === "object") checkAst(value);
}
for (const provider of ["cloudflare", "netlify", "vercel", "esa", "edgeone"]) {
  const result = await build({
    entryPoints: [`examples/cloud/${provider}.ts`],
    bundle: true,
    platform: "browser",
    format: "esm",
    target: "es2022",
    write: false,
    metafile: true,
  });
  const code = result.outputFiles[0].text;
  checkAst(parse(code, { ecmaVersion: "latest", sourceType: "module" }));
  let origins = 0;
  const context = createContext(
    {
      Request,
      Response,
      URL,
      Headers,
      ReadableStream,
      TextEncoder,
      TextDecoder,
      crypto,
      AbortController,
      AbortSignal,
      setTimeout,
      clearTimeout,
      structuredClone,
      console,
      fetch: async (url) => {
        const u = new URL(url);
        if (u.hostname === "control.test")
          return Response.json(
            u.pathname === "/v1/generation" ? { generation: 0 } : { decision: null },
          );
        if (u.hostname === "origin.test") {
          origins++;
          return new Response(null, { status: 204 });
        }
        throw new Error("Unexpected sandbox network destination");
      },
    },
    { codeGeneration: { strings: false, wasm: false } },
  );
  const module = new SourceTextModule(code, { context });
  await module.link(() => {
    throw new Error("Bundle has unresolved imports");
  });
  await module.evaluate();
  const env = {
    TENANT: "sandbox",
    SERVICE: "api",
    PUBLIC_HOST: "api.test",
    ORIGIN: "https://origin.test",
    ORIGIN_TOKEN: "sandbox-origin-token-never-transmitted",
    CONTROL_ORIGIN: "https://control.test",
    CONTROL_RUNTIME_TOKEN: "sandbox-control-token-never-transmitted",
    ROUTES: [{ path: "/api", methods: ["GET"], authenticated: false }],
    POLICY: JSON.stringify({
      version: "1",
      rules: [
        {
          id: "sandbox-rule",
          name: "regex sandbox",
          service: "api",
          when: { field: "query", key: "q", op: "regex", value: "attack$" },
          then: { action: "block" },
        },
      ],
    }),
  };
  const ns = module.namespace;
  let handler;
  if (provider === "cloudflare") handler = (req) => ns.default.fetch(req, env);
  else if (provider === "vercel") handler = ns.vercelHandler(env, () => "192.0.2.1");
  else if (provider === "netlify")
    handler = (req) => ns.netlifyHandler(env)(req, { ip: "192.0.2.1" });
  else handler = ns[`${provider}Handler`](env);
  if ((await handler(new Request("https://api.test/api?q=attack"))).status !== 403 || origins !== 0)
    throw new Error(`${provider}: sandbox block failed`);
  if ((await handler(new Request("https://api.test/api?q=normal"))).status !== 204 || origins !== 1)
    throw new Error(`${provider}: sandbox proxy failed`);
  console.log(
    `${provider}: ${result.outputFiles[0].contents.length} bytes; browser ESM, no dynamic code, sandbox block/proxy passed`,
  );
}
