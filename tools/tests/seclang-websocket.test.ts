import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { checkBoundary, limitsWith } from "../../scr/http-boundary/index.js";

test("complete CRS inspects native WebSocket handshakes and 101 headers while preserving binary frames", {
  timeout: 45000,
}, async () => {
  const output = await build({
    stdin: {
      contents: `
    import {createShield} from './scr/runtime/index.ts';
    import {createPCRE2Backend,createInjectionDetectors} from './scr/seclang/index.ts';
    import rules from './rules/seclang-bundle.json';
    import PCRE from './pcre2.wasm';import INJECTION from './libinjection.wasm';
    let engine;
    export default {async fetch(request) {
      engine ??= Promise.all([createPCRE2Backend(PCRE),createInjectionDetectors(INJECTION)]).then(([regexBackend,detectors])=>createShield({tenant:'test',service:'connect',publicHosts:['test'],
        routes:[{path:'/ws',business:'connect',methods:['GET'],authenticated:false,websocket:true},{path:'/http',business:'connect',methods:['GET'],authenticated:false}],
        secLang:rules.source+'\\nSecRule RESPONSE_HEADERS:x-origin-reject "@streq yes" "id:10001,phase:3,deny"',secLangOptions:{files:rules.files,regexBackend,detectors},
        origins:{connect:{origin:'https://origin.test',allowedOrigins:['https://origin.test'],originToken:'test-websocket-origin-token-32-characters',fetch:async(input,init)=>{
          if(new Headers(init.headers).get('upgrade')!=='websocket')return new Response('ordinary');
          const pair=new WebSocketPair();pair[1].binaryType="arraybuffer";pair[1].accept();pair[1].addEventListener('message',e=>pair[1].send(e.data));
          return new Response(null,{status:101,webSocket:pair[0],headers:{'x-shield-private':'must-not-leak','x-origin-reject':new URL(input).searchParams.has('response')?'yes':'no'}});
        }}}}));
      const headers=new Headers(request.headers);headers.set('host','test');
      return (await engine).handle(new Request(request,{headers}),{tenant:'test',verifiedClientIp:'192.0.2.1',httpProtocol:'HTTP/1.1'});
    }};
  `,
      resolveDir: process.cwd(),
    },
    bundle: true,
    format: "esm",
    platform: "browser",
    write: false,
    external: ["*.wasm"],
  });
  const directory = resolve("tools/.cache/ws-test");
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      cf: false,
      modulesRoot: directory,
      compatibilityDate: "2026-10-01",
      modules: [
        {
          type: "ESModule",
          path: resolve(directory, "worker.js"),
          contents: output.outputFiles[0]!.text,
        },
        ...(await Promise.all(
          ["pcre2", "libinjection"].map(async (name) => ({
            type: "CompiledWasm" as const,
            path: resolve(directory, `${name === "pcre2" ? "pcre2" : "libinjection"}.wasm`),
            contents: await readFile(resolve("scr/seclang/vendor", `${name}.wasm`)),
          })),
        )),
      ],
    }),
  );
  const headers = {
    upgrade: "websocket",
    connection: "Upgrade",
    "sec-websocket-version": "13",
    "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
    "user-agent": "Mozilla/5.0",
    accept: "*/*",
  };
  try {
    const normal = await mf.dispatchFetch("https://test/ws", { headers });
    assert.equal(normal.status, 101);
    assert.equal(normal.headers.has("x-shield-private"), false);
    const socket = normal.webSocket!;
    socket.accept();
    const received = new Promise<Uint8Array>((done, reject) => {
      const timer = setTimeout(() => reject(Error("Echo timeout")), 3000);
      socket.addEventListener(
        "message",
        (event) => {
          clearTimeout(timer);
          if (typeof event.data === "string") {
            reject(new Error("Binary echo became text"));
            return;
          }
          Promise.resolve(event.data instanceof Blob ? event.data.arrayBuffer() : event.data).then(
            (value) => done(new Uint8Array(value)),
            reject,
          );
        },
        { once: true },
      );
    });
    socket.send(new Uint8Array([0, 1, 255, 3]).buffer);
    assert.deepEqual(new Uint8Array(await received), new Uint8Array([0, 1, 255, 3]));
    socket.close();
    assert.equal((await mf.dispatchFetch("https://test/http", { headers })).status, 426);
    assert.equal(
      (
        await mf.dispatchFetch("https://test/ws?q=1%20UNION%20SELECT%20password%20FROM%20users", {
          headers,
        })
      ).status,
      403,
    );
    assert.equal((await mf.dispatchFetch("https://test/ws?response=yes", { headers })).status, 403);
  } finally {
    await mf.dispose();
  }
});

test("WebSocket routes still reject malformed handshakes, framing and unsupported upgrades", () => {
  const headers = {
    upgrade: "websocket",
    "sec-websocket-version": "13",
    "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
  };
  for (const extra of [
    { "sec-websocket-key": "invalid" },
    { "sec-websocket-version": "12" },
    { upgrade: "h2c" },
    { "transfer-encoding": "chunked" },
    { connection: "authorization" },
  ]) {
    assert.throws(() =>
      checkBoundary(
        new Request("https://test/ws", { headers: { ...headers, ...extra } }),
        limitsWith(),
        ["test"],
        undefined,
        "websocket",
      ),
    );
  }
  assert.throws(() =>
    checkBoundary(new Request("https://test/ws", { headers }), limitsWith(), ["test"]),
  );
});
