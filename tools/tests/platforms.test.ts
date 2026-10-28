import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { signIngress, verifyIngress } from "../../scr/adapters/ingress.js";
// @ts-expect-error Build tool is deliberately an executable ES module.
import { buildPlatform } from "../build-platform.mjs";

const ingressKey = "test-ingress-key-".repeat(4),
  metadata = { httpProtocol: "HTTP/2", verifiedClientIp: "192.0.2.5" };
test("ingress metadata is bound to method, complete URL, signature and timestamp", async () => {
  const request = new Request("https://test/api?q=hello");
  const signature = await signIngress(request, metadata, ingressKey);
  const signed = new Request(request, { headers: { "x-edgeshield-ingress": signature } });
  assert.deepEqual(await verifyIngress(signed, ingressKey), metadata);
  await assert.rejects(
    verifyIngress(
      new Request("https://test/api?q=changed", { headers: signed.headers }),
      ingressKey,
    ),
    /mismatch/,
  );
  await assert.rejects(verifyIngress(signed, ingressKey, Date.now() + 31000), /Invalid/);
  await assert.rejects(verifyIngress(signed, "wrong-key-".repeat(5)), /mismatch/);
});
test("all five built entry points execute the complete CRS and only their own business origin", {
  timeout: 90000,
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "shield-platforms-"));
  try {
    await mkdir(join(directory, "secret"));
    await mkdir(join(directory, "respond"));
    await writeFile(
      join(directory, "secret/credentials.yml"),
      JSON.stringify({ originToken: "test-origin-secret-".repeat(3), ingressKey }),
    );
    await writeFile(join(directory, "respond/403.html"), "<html><p>custom rejection</p></html>");
    await writeFile(join(directory, "respond/403.json"), '{"error":"operator_custom_denial"}');
    const configFile = join(directory, "config.yml");
    await writeFile(
      configFile,
      JSON.stringify({
        tenant: "test",
        service: "api",
        platform: "cloudflare",
        publicHosts: ["api.test"],
        secLangFile: resolve("rules/seclang-bundle.json"),
        secretFile: "secret/credentials.yml",
        originDirectory: "origin",
        routes: [
          {
            business: "app",
            path: "/api",
            methods: ["GET", "POST"],
            authenticated: false,
            body: "text",
          },
          { business: "shop", path: "/shop", methods: ["GET"], authenticated: false },
        ],
        listen: { host: "127.0.0.1", port: 0 },
        responses: { directory: "respond", contentSecurityPolicy: "default-src 'none'" },
        limits: { maxBodyBytes: 8388608 },
      }),
    );
    for (const platform of ["cloudflare", "vercel", "netlify", "esa", "edgeone"]) {
      await mkdir(join(directory, "origin", platform, "app"), { recursive: true });
      await writeFile(
        join(directory, "origin", platform, "app", "config.yml"),
        JSON.stringify({ platform, mode: "function" }),
      );
      await writeFile(
        join(directory, "origin", platform, "app", "index.js"),
        `export default{fetch(request){return new Response(new URL(request.url).searchParams.has('leak')?'<title>=[ 1n73ct10n privat shell ]=</title>':${JSON.stringify(`business_${platform}`)},{headers:{'content-type':'text/html'}})}}`,
      );
    }
    for (const platform of ["cloudflare", "vercel", "netlify", "esa", "edgeone"]) {
      await mkdir(join(directory, "origin", platform, "shop"), { recursive: true });
      await writeFile(
        join(directory, "origin", platform, "shop", "config.yml"),
        JSON.stringify({ platform, mode: "function" }),
      );
      await writeFile(
        join(directory, "origin", platform, "shop", "index.js"),
        `export default{fetch(){return new Response('shop_${platform}',{headers:{'content-type':'text/html'}})}}`,
      );
      const built = await buildPlatform(platform, configFile);
      assert.ok(
        built.inputs.some((path: string) =>
          path.replaceAll("\\", "/").includes(`/origin/${platform}/app/index.js`),
        ),
      );
      assert.equal(
        built.inputs.filter((path: string) =>
          /\/origin\/(cloudflare|vercel|netlify|esa|edgeone)\//.test(path.replaceAll("\\", "/")),
        ).length,
        2,
      );
      let dispatch: (request: Request) => Promise<Response>,
        dispose = async () => {};
      if (platform === "cloudflare") {
        // Miniflare's local TCP bridge overwrites Host with its loopback socket.
        // Restore the dispatched authority before entering the unmodified built worker.
        const bridge = `import worker from './worker.js';export default{fetch(r,e,c){const headers=new Headers(r.headers);headers.set('host',new URL(r.url).host);return worker.fetch(new Request(r,{headers}),e,c);}};`;
        const mf = new Miniflare(
          convertV4MiniflareOptions({
            cf: false,
            modulesRoot: built.directory,
            modules: [
              { type: "ESModule", path: join(built.directory, "test-bridge.js"), contents: bridge },
              {
                type: "ESModule",
                path: built.entry,
                contents: await readFile(built.entry, "utf8"),
              },
              ...(await Promise.all(
                ["pcre2", "libinjection"].map(async (name) => ({
                  type: "CompiledWasm" as const,
                  path: join(built.directory, `${name}.wasm`),
                  contents: await readFile(join(built.directory, `${name}.wasm`)),
                })),
              )),
            ],
            compatibilityDate: "2026-10-01",
          }),
        );
        dispatch = async (request) =>
          mf.dispatchFetch(request.url, {
            method: request.method,
            headers: Object.fromEntries(request.headers),
            cf: { httpProtocol: "HTTP/2" },
          }) as unknown as Promise<Response>;
        dispose = () => mf.dispose();
      } else {
        const module = await import(`${pathToFileURL(built.entry).href}?test=${Date.now()}`);
        dispatch =
          platform === "edgeone"
            ? (request) => module.onRequest({ request })
            : platform === "netlify"
              ? module.default
              : (request) => module.default.fetch(request);
      }
      const send = async (query: string, html = false, path = "/api") => {
        const request = new Request(`https://api.test${path}${query}`, {
          headers: {
            host: "api.test",
            "user-agent": "Mozilla/5.0",
            accept: html ? "text/html" : "application/json",
            "cf-connecting-ip": "192.0.2.5",
          },
        });
        request.headers.set(
          "x-edgeshield-ingress",
          await signIngress(request, metadata, ingressKey),
        );
        return dispatch(request);
      };
      try {
        const normal = await send("?q=hello");
        assert.equal(normal.status, 200, `${platform}: normal`);
        assert.equal(await normal.text(), `business_${platform}`);
        const shop = await send("", false, "/shop");
        assert.equal(shop.status, 200);
        assert.equal(await shop.text(), `shop_${platform}`);
        for (const attack of [
          "1 UNION SELECT password FROM users",
          "<script>alert(1)</script>",
          "../../../../etc/passwd",
          ";cat /etc/passwd",
        ]) {
          const response = await send(`?q=${encodeURIComponent(attack)}`);
          assert.equal(response.status, 403, `${platform}: attack ${attack}`);
          assert.deepEqual(await response.json(), { error: "operator_custom_denial" });
          const shopAttack = await send(`?q=${encodeURIComponent(attack)}`, false, "/shop");
          assert.equal(shopAttack.status, 403, `${platform}: shop attack`);
          await shopAttack.text();
        }
        const leak = await send("?leak=yes", true);
        assert.equal(leak.status, 403, `${platform}: response CRS`);
        assert.match(await leak.text(), /custom rejection/);
      } finally {
        await dispose();
      }
    }
    // A foreign platform business import is rejected, including transitive imports.
    await writeFile(
      join(directory, "origin/vercel/app/index.js"),
      "export{default}from '../../netlify/app/index.js'",
    );
    await assert.rejects(buildPlatform("vercel", configFile), /Cross-platform/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
