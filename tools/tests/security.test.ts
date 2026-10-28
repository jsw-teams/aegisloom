import assert from "node:assert/strict";
import { once } from "node:events";
import { connect } from "node:net";
import { test } from "node:test";
import { canonicalPath, checkRawHeaders } from "../../scr/http-boundary/index.js";
import { parseStrictJson } from "../../scr/http-boundary/json.js";
import { createNodeServer } from "../../scr/runtime/node.js";
import { context, fixture, request } from "./helpers.js";

test("ambiguous and double encoded paths are rejected before URL parsing", () => {
  for (const path of [
    "//evil",
    "/a/../api",
    "/%2e%2e/api",
    "/%252e/api",
    "/a%2fb",
    "/a\\b",
    "/a;b",
    "/a//b",
    "/%00",
    "/%zz",
  ])
    assert.throws(() => canonicalPath(path), path);
  assert.equal(canonicalPath("/caf%C3%A9"), "/café");
});
test("raw header ambiguity checks and strict JSON reject parser differentials", () => {
  assert.throws(() => checkRawHeaders(["Content-Length", "1", "content-length", "1"]));
  assert.throws(() => checkRawHeaders(["Transfer-Encoding", "chunked", "Content-Length", "1"]));
  for (const json of [
    '{"x":"safe","x":"attack"}',
    '{"x":0,"\\u0078":1}',
    "1e999",
    `${"[".repeat(35)}0${"]".repeat(35)}`,
    '{"a":1,}',
  ])
    assert.throws(() => parseStrictJson(json));
  assert.deepEqual(parseStrictJson('{"a":[1,true,null]}'), { a: [1, true, null] });
});
test("header host, framing, compression, multipart and body limits", async () => {
  const f = await fixture({ limits: { maxBodyBytes: 16 } });
  for (const headers of [
    { host: "evil.test" },
    { "content-length": "1, 1" },
    { "transfer-encoding": "chunked", "content-length": "1" },
    { connection: "authorization" },
    { "content-encoding": "gzip" },
  ]) {
    assert.ok((await f.handle(request("", { headers }), context)).status >= 400);
  }
  assert.equal(
    (await f.handle(request("", { method: "POST", body: "x".repeat(17) }), context)).status,
    413,
  );
  assert.equal(f.forwarded.length, 0);
});
test("bounded body read times out a never ending stream", async () => {
  const f = await fixture({ limits: { bodyTimeoutMs: 10 } });
  const req = request("", {
    method: "POST",
    body: new ReadableStream({
      start(c) {
        c.enqueue(new Uint8Array([1]));
      },
    }),
    duplex: "half",
  } as RequestInit);
  assert.equal((await f.handle(req, context)).status, 408);
});
test("SSRF origins and unsafe protocols are rejected at configuration time", async () => {
  for (const origin of [
    "http://169.254.169.254",
    "https://origin.test/path",
    "https://evil.test",
    "https://user:pass@origin.test",
  ])
    await assert.rejects(
      fixture({
        origins: {
          app: { origin, allowedOrigins: ["https://origin.test"], originToken: "x".repeat(32) },
        },
      }),
    );
});
test("local raw socket TE.CL regression: parser rejects before handler; loopback only", async () => {
  let handled = 0;
  const server = createNodeServer(async () => {
    handled++;
    return new Response("ok");
  }, "127.0.0.1");
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  try {
    const socket = connect(addr.port, "127.0.0.1");
    let result = "";
    socket.on("data", (d) => {
      result += d.toString();
    });
    socket.write(
      "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
    );
    await once(socket, "close");
    assert.match(result, /400 Bad Request/);
    assert.equal(handled, 0);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
