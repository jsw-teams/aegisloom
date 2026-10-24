import assert from "node:assert/strict";
import { test } from "node:test";
import { createProxy } from "../packages/runtime/proxy.js";
import { context, fixture, request, token } from "./helpers.js";

const options = {
  origin: "https://origin.test",
  allowedOrigins: ["https://origin.test"],
  originToken: token,
};

test("proxy never follows redirects or leaks internal response headers; multiple cookies preserved", async () => {
  const proxy = createProxy({
    ...options,
    fetch: async (_, init) => {
      assert.equal(init?.redirect, "manual");
      return new Response(null, {
        status: 302,
        headers: [
          ["location", "http://169.254.169.254/"],
          ["x-shield-origin-auth", "secret"],
          ["connection", "x-private"],
          ["x-private", "drop"],
          ["set-cookie", "a=1; HttpOnly"],
          ["set-cookie", "b=2; HttpOnly"],
        ],
      });
    },
  });
  const r = request();
  const result = await proxy(r, new URL(r.url), "/api", new Uint8Array());
  assert.equal(result.status, 302);
  assert.equal(result.headers.has("x-shield-origin-auth"), false);
  assert.equal(result.headers.has("x-private"), false);
  assert.equal(result.headers.getSetCookie().length, 2);
});
test("upstream TLS/network failure returns 502 and opens a bounded circuit", async () => {
  let calls = 0;
  const f = await fixture({
    proxy: {
      ...options,
      fetch: async () => {
        calls++;
        throw new Error("simulated TLS failure");
      },
    },
  });
  for (let i = 0; i < 5; i++) assert.equal((await f.handle(request(), context)).status, 502);
  assert.equal((await f.handle(request(), context)).status, 503);
  assert.equal(calls, 5);
});
test("origin handshake timeout aborts and compressed responses are rejected", async () => {
  const timeout = await fixture({
    proxy: {
      ...options,
      timeoutMs: 10,
      fetch: async (_, init) =>
        new Promise((_, reject) =>
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), {
            once: true,
          }),
        ),
    },
  });
  assert.equal((await timeout.handle(request(), context)).status, 504);
  const compressed = await fixture({
    proxy: {
      ...options,
      fetch: async () => new Response("x", { headers: { "content-encoding": "gzip" } }),
    },
  });
  assert.equal((await compressed.handle(request(), context)).status, 502);
});
test("streaming response resource bound errors rather than silently truncating", async () => {
  const f = await fixture({
    proxy: { ...options, maxResponseBytes: 4, fetch: async () => new Response("too large") },
  });
  await assert.rejects((await f.handle(request(), context)).text(), /too-large/);
});
test("concurrency slots stay held for unconsumed responses and release on cancel", async () => {
  const f = await fixture({ maxConcurrentRequests: 1 });
  const first = await f.handle(request(), context);
  assert.equal((await f.handle(request(), context)).status, 503);
  await first.body?.cancel();
  const next = await f.handle(request(), context);
  assert.equal(next.status, 200);
  await next.body?.cancel();
});
test("stream deadline aborts a stalled response and releases concurrency capacity", async () => {
  const f = await fixture({
    maxConcurrentRequests: 1,
    proxy: { ...options, timeoutMs: 10, fetch: async () => new Response(new ReadableStream()) },
  });
  const response = await f.handle(request(), context);
  await assert.rejects(response.text(), /aborted/);
  const second = await f.handle(request(), context);
  assert.equal(second.status, 200);
  await second.body?.cancel();
});
