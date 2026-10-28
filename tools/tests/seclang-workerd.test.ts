import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { parseSecLangSyntax } from "../../scr/seclang/syntax.js";

test("real workerd executes PCRE2 and libinjection from precompiled WASM bindings", {
  timeout: 45000,
}, async () => {
  const bundle = await build({
    stdin: {
      contents: `
    import {compileSecLang,executeSecLang,createPCRE2Backend,createInjectionDetectors} from './scr/seclang/index.ts';
    import PCRE2 from './pcre2.wasm';
    import INJECTION from './libinjection.wasm';
    import RULES from './rules/seclang-bundle.json';
    let program, fullProgram;
    export default {async fetch(request,env){
      if(new URL(request.url).pathname==='/full'){
        fullProgram ??= Promise.all([createPCRE2Backend(PCRE2),createInjectionDetectors(INJECTION)]).then(([regexBackend,detectors])=>compileSecLang(RULES.source,{strict:true,files:RULES.files,regexBackend,detectors}));
        const vm=await fullProgram;
        const input={url:request.url,method:request.method,protocol:'HTTP/1.1',remoteAddr:'192.0.2.5',headers:{host:'test','user-agent':'Mozilla/5.0',accept:'text/html'}};
        const incoming=executeSecLang(vm,input);
        const result=incoming.blocked?incoming:executeSecLang(vm,{...input,responseStatus:200,responseHeaders:{'content-type':'text/html'},responseBody:request.headers.get('x-test-response')??'Hello'},{phases:[3,4,5],transaction:incoming.transaction});
        return Response.json({blocked:result.blocked,matched:result.matched,rules:vm.sourceRules,unsupported:vm.unsupported.length},{status:result.status});
      }
      program ??= Promise.all([createPCRE2Backend(PCRE2),createInjectionDetectors(INJECTION)]).then(([regexBackend,detectors])=>compileSecLang(
        'SecRule ARGS "@rx (?<=prefix:)([a-z]+)-\\\\1$" "id:45001,deny,capture"\\n'.replace('\\\\n','\\n')+
        'SecRule ARGS "@detectSQLi" "id:45002,deny,capture"', {strict:true,regexBackend,detectors}));
      const result=executeSecLang(await program,{url:request.url,method:request.method,headers:request.headers});
      return Response.json({blocked:result.blocked,matched:result.matched,tx:result.tx},{status:result.status});
    }};
  `,
      resolveDir: process.cwd(),
    },
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    write: false,
    external: ["*.wasm"],
  });
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      cf: false,
      modulesRoot: resolve("tools/.cache/seclang-workerd"),
      modules: [
        {
          type: "ESModule",
          path: resolve("tools/.cache/seclang-workerd/worker.mjs"),
          contents: bundle.outputFiles[0]!.text,
        },
        {
          type: "CompiledWasm",
          path: resolve("tools/.cache/seclang-workerd/pcre2.wasm"),
          contents: await readFile(new URL("../../scr/seclang/vendor/pcre2.wasm", import.meta.url)),
        },
        {
          type: "CompiledWasm",
          path: resolve("tools/.cache/seclang-workerd/libinjection.wasm"),
          contents: await readFile(
            new URL("../../scr/seclang/vendor/libinjection.wasm", import.meta.url),
          ),
        },
      ],
      compatibilityDate: "2026-10-01",
    }),
  );
  try {
    assert.equal((await mf.dispatchFetch("https://test/?q=prefix:abc-abc")).status, 403);
    assert.equal(
      (
        await mf.dispatchFetch(
          `https://test/?q=${encodeURIComponent("1 UNION SELECT password FROM users")}`,
        )
      ).status,
      403,
    );
    assert.equal((await mf.dispatchFetch("https://test/?q=normal")).status, 200);
    const normal = await mf.dispatchFetch("https://test/full?q=hello");
    assert.equal(normal.status, 200);
    const sourceBundle = JSON.parse(
      await readFile(new URL("../../rules/seclang-bundle.json", import.meta.url), "utf8"),
    );
    const expectedRules = Object.entries(sourceBundle.files)
      .filter(([name]) => name.endsWith(".conf"))
      .reduce(
        (count, [, text]) =>
          count +
          parseSecLangSyntax(text as string).filter((s) => s.directive === "SecRule").length,
        0,
      );
    assert.deepEqual(await normal.json().then((body: any) => [body.rules, body.unsupported]), [
      expectedRules,
      0,
    ]);
    for (const attack of [
      "1 UNION SELECT password FROM users",
      "<script>alert(1)</script>",
      "../../../../etc/passwd",
    ]) {
      const result = await mf.dispatchFetch(`https://test/full?q=${encodeURIComponent(attack)}`);
      assert.equal(result.status, 403);
      assert.ok(((await result.json()) as any).matched.includes("949110"));
    }
    const responseAttack = await mf.dispatchFetch("https://test/full", {
      headers: { "x-test-response": "<title>=[ 1n73ct10n privat shell ]=</title>" },
    });
    assert.equal(responseAttack.status, 403);
    assert.ok(((await responseAttack.json()) as any).matched.includes("955100"));
  } finally {
    await mf.dispose();
  }
});
