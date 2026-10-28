import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { readCredentials, readData } from "../scr/cli/config.ts";
import { readDeployment } from "../scr/cli/deployment.ts";
import { readResponsePages } from "../scr/cli/responses.ts";
import { compileSecLang } from "../scr/seclang/index.ts";
import { loadSecLangDeployment } from "../scr/seclang/node.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export async function buildPlatform(platform, configFile = resolve(root, "config.yml")) {
  if (!["cloudflare", "vercel", "netlify", "esa", "edgeone"].includes(platform))
    throw new Error("Unknown deployment platform");
  const { config, businesses, originRoot, platformRoot } = await readDeployment(
    configFile,
    platform,
  );
  const credentials = await readCredentials(config.secretFile),
    native = await loadSecLangDeployment(config.secLangFile, config.localRulesFile);
  const program = compileSecLang(native.secLang, { ...native.secLangOptions, strict: true });
  program.dispose();
  const data = {
    config,
    credentials,
    source: native.secLang,
    files: native.secLangOptions.files,
    allowlist: config.allowlistFile ? await readData(config.allowlistFile) : [],
    errorPages: config.responses
      ? await readResponsePages(config.responses.directory, config.responses.contentSecurityPolicy)
      : {},
  };
  // Only the selected platform's business is bundled.
  const directory = resolve(root, "tools/.cache/platforms", platform);
  await mkdir(directory, { recursive: true });
  const rel = (path) => JSON.stringify(path.replaceAll("\\", "/"));
  const imports = [],
    transports = [];
  for (const [name, { settings, businessFile }] of Object.entries(businesses)) {
    const id = imports.length;
    if (settings.mode === "function") {
      imports.push(`import business${id} from ${rel(businessFile)};`);
      transports.push(
        `${JSON.stringify(name)}:(input,init)=>Promise.resolve(business${id}.fetch(new Request(input,init)))`,
      );
    } else if (settings.mode === "proxy")
      transports.push(`${JSON.stringify(name)}:(input,init)=>fetch(input,init)`);
    else {
      imports.push(
        `import {createRelayTransport as createRelay${id}}from ${rel(resolve(root, "scr/origin/relay.ts"))};const transport${id}=createRelay${id}(${JSON.stringify({ endpoint: settings.endpoint, serverPublicKey: await readData(settings.publicKeyFile, 16384), authenticationKey: await readData(settings.authenticationKeyFile, 4096), maxBytes: config.limits?.maxBodyBytes ?? 8388608 })});`,
      );
      transports.push(
        `${JSON.stringify(name)}:async(input,init)=>(await transport${id})(input,init)`,
      );
    }
  }
  const origin = `${imports.join("\n")}\nexport default {${transports.join(",")}};`;
  const wasm = [];
  for (const name of ["pcre2", "libinjection"])
    wasm.push(await readFile(resolve(root, "scr/seclang/vendor", `${name}.wasm`)));
  const wasmSource =
    platform === "cloudflare"
      ? `import PCRE2 from './pcre2.wasm';import INJECTION from './libinjection.wasm';export{PCRE2,INJECTION};`
      : `const decode=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));export const PCRE2=decode('${wasm[0].toString("base64")}'),INJECTION=decode('${wasm[1].toString("base64")}');`;
  const allowed = platformRoot;
  const result = await build({
    entryPoints: [resolve(root, `scr/adapters/${platform}/worker.ts`)],
    bundle: true,
    write: false,
    metafile: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    outdir: directory,
    sourcemap: false,
    logLevel: "silent",
    external: ["*.wasm"],
    plugins: [
      {
        name: "private-project-assets",
        setup(api) {
          api.onResolve({ filter: /^edgeshield:/ }, (args) => ({
            path: args.path,
            namespace: "project",
          }));
          api.onLoad({ filter: /.*/, namespace: "project" }, (args) => ({
            contents:
              args.path === "edgeshield:deployment"
                ? `export default ${JSON.stringify(data)};`
                : args.path === "edgeshield:origin"
                  ? origin
                  : wasmSource,
            loader: "js",
            resolveDir: directory,
          }));
          // Reject even transitive imports of another platform's business files.
          api.onLoad({ filter: /.*/ }, (args) => {
            const inside = relative(originRoot, args.path);
            if (!inside.startsWith("..") && !isAbsolute(inside)) {
              const own = relative(allowed, args.path);
              if (own.startsWith("..") || isAbsolute(own))
                throw new Error("Cross-platform origin import is forbidden");
            }
            return undefined;
          });
        },
      },
    ],
  });
  for (const output of result.outputFiles)
    await writeFile(output.path, output.contents, { mode: 0o600 });
  if (platform === "cloudflare")
    for (let i = 0; i < wasm.length; i++)
      await writeFile(join(directory, `${i ? "libinjection" : "pcre2"}.wasm`), wasm[i]);
  if (Object.keys(result.metafile.inputs).some((path) => /secret\/relay\/private/.test(path)))
    throw new Error("Relay private key must not enter a cloud build");
  return {
    directory,
    entry: join(directory, "worker.js"),
    inputs: Object.keys(result.metafile.inputs),
    bytes: result.outputFiles.reduce((n, file) => n + file.contents.length, 0),
  };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await buildPlatform(
    process.argv[2],
    process.argv[3] ? resolve(process.argv[3]) : undefined,
  );
  console.log(JSON.stringify({ directory: result.directory, bytes: result.bytes }));
}
