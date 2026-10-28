import assert from "node:assert/strict";
import { test } from "node:test";
import { createShield } from "../../scr/runtime/index.js";
import { compileSecLang, executeSecLang } from "./seclang-helpers.js";

test("logging phase executes after an earlier phase interrupts the transaction", () => {
  const vm = compileSecLang(
    'SecRule ARGS:q "@contains attack" "id:46001,deny"\nSecAction "id:46002,phase:5,pass,setvar:tx.logged=1"\nSecAction "id:46003,phase:5,pass,setvar:tx.logged=+1"',
    { strict: true },
  );
  const result = executeSecLang(
    vm,
    { url: "https://test/?q=attack", method: "GET" },
    { phases: [1, 2, 3, 4, 5] },
  );
  assert.equal(result.blocked, true);
  assert.equal(result.tx.logged, 2);
  assert.deepEqual(result.matched, ["46001", "46002", "46003"]);
});

test("initcol and setvar persist actual per-IP state across transactions", () => {
  const vm = compileSecLang(
    'SecAction "id:46004,phase:1,initcol:ip=%{remote_addr},setvar:ip.requests=+1"\nSecRule IP:requests "@gt 1" "id:46005,deny"',
    { strict: true },
  );
  const request = { url: "https://test/", method: "GET", remoteAddr: "192.0.2.1" };
  assert.equal(executeSecLang(vm, request).blocked, false);
  assert.equal(executeSecLang(vm, request).blocked, true);
  assert.equal(executeSecLang(vm, { ...request, remoteAddr: "192.0.2.2" }).blocked, false);
});

test("native multipart parser inspects fields and preserves binary upload bytes through the proxy", async () => {
  const received: number[][] = [];
  const shield = await createShield({
    tenant: "test",
    service: "api",
    publicHosts: ["test"],
    routes: [{ business: "app", path: "/", methods: ["POST"], authenticated: false, body: "text" }],
    secLang: 'SecRule ARGS:q "@contains attack" "id:46006,deny"',
    origins: {
      app: {
        origin: "https://origin.test",
        allowedOrigins: ["https://origin.test"],
        originToken: "a-long-enough-origin-token-never-sent-elsewhere",
        fetch: async (_request, init) => {
          received.push([...new Uint8Array(await new Response(init?.body).arrayBuffer())]);
          return new Response("ok");
        },
      },
    },
  });
  const prefix = new TextEncoder().encode(
    '--upload\r\nContent-Disposition: form-data; name="file"; filename="data.bin"\r\nContent-Type: application/octet-stream\r\n\r\n',
  );
  const suffix = new TextEncoder().encode(
    '\r\n--upload\r\nContent-Disposition: form-data; name="q"\r\n\r\nhello\r\n--upload--\r\n',
  );
  const bytes = new Uint8Array([...prefix, 0, 255, 128, ...suffix]);
  const send = (body: Uint8Array) =>
    shield.handle(
      new Request("https://test/", {
        method: "POST",
        headers: { "content-type": "multipart/form-data; boundary=upload" },
        body: body as BodyInit,
      }),
      { tenant: "test" },
    );
  assert.equal(await (await send(bytes)).text(), "ok");
  assert.deepEqual(received, [Array.from(bytes)]);
  const attack = new TextEncoder().encode(
    '--upload\r\nContent-Disposition: form-data; name="q"\r\n\r\nattack\r\n--upload--\r\n',
  );
  assert.equal((await send(attack)).status, 403);
  assert.equal(received.length, 1);
  shield.dispose();
  assert.equal((await send(bytes)).status, 503);
});
