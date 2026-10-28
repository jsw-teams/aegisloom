import assert from "node:assert/strict";
import { resolve } from "node:path";
import { test } from "node:test";
import { createShield } from "../../scr/runtime/index.js";
import { loadSecLangFile } from "../../scr/seclang/node.js";

test("complete CRS permits configured large multipart uploads and enforces actual byte limits", async () => {
  const native = await loadSecLangFile(resolve("rules/seclang-bundle.json"));
  let forwarded = 0;
  const engine = await createShield({
    tenant: "test",
    service: "upload",
    publicHosts: ["api.test"],
    routes: [
      { business: "app", path: "/upload", methods: ["POST"], body: "text", authenticated: false },
    ],
    ...native,
    limits: { maxBodyBytes: 8 * 1024 * 1024 },
    origins: {
      app: {
        origin: "https://origin.test",
        allowedOrigins: ["https://origin.test"],
        originToken: "test-only-origin-token-".repeat(3),
        fetch: async (_input, init) => {
          assert.ok(init?.body instanceof Uint8Array);
          forwarded = init.body.length;
          return Response.json({ ok: true });
        },
      },
    },
  });
  const context = { tenant: "test", verifiedClientIp: "192.0.2.5", httpProtocol: "HTTP/1.1" };
  const request = (data: BodyInit, extra: Record<string, string> = {}) =>
    new Request("https://api.test/upload", {
      method: "POST",
      headers: {
        host: "api.test",
        "user-agent": "Mozilla/5.0",
        accept: "application/json",
        "content-type": "multipart/form-data; boundary=upload-boundary",
        ...extra,
      },
      body: data,
      duplex: "half",
    } as RequestInit);
  const multipart = (size: number) =>
    `--upload-boundary\r\nContent-Disposition: form-data; name="upload"; filename="report.pdf"\r\nContent-Type: application/pdf\r\n\r\n${"a".repeat(size)}\r\n--upload-boundary--\r\n`;
  try {
    const body = multipart(3 * 1024 * 1024);
    const response = await engine.handle(request(body), context);
    assert.equal(response.status, 200, await response.clone().text());
    await response.text();
    assert.equal(forwarded, body.length);
    const oversized = multipart(8 * 1024 * 1024);
    const denied = await engine.handle(request(oversized, { "content-length": "1" }), context);
    assert.equal(denied.status, 413);
    assert.equal(forwarded, body.length);
    const attack = await engine.handle(
      request(
        multipart(10).replace(
          "--upload-boundary--\r\n",
          '--upload-boundary\r\nContent-Disposition: form-data; name="query"\r\n\r\n1 UNION SELECT password FROM users\r\n--upload-boundary--\r\n',
        ),
      ),
      context,
    );
    assert.equal(attack.status, 403);
  } finally {
    engine.dispose();
  }
});
