import assert from "node:assert/strict";
import { test } from "node:test";
import { createShield } from "../../scr/runtime/index.js";

async function engine(
  source: string,
  allowlist: Array<{
    id: string;
    skip: "rules"[];
    ruleIds?: string[];
  }> = [],
) {
  let forwarded = 0;
  const shield = await createShield({
    tenant: "test",
    service: "api",
    publicHosts: ["example.test"],
    routes: [
      {
        business: "app",
        path: "/api",
        methods: ["GET", "POST"],
        authenticated: false,
        body: "text",
      },
    ],
    secLang: source,
    allowlist,
    origins: {
      app: {
        origin: "https://backend.test",
        allowedOrigins: ["https://backend.test"],
        originToken: "a-secret-long-enough-to-be-an-origin-token",
        fetch: async () => {
          forwarded++;
          return new Response("origin ok");
        },
      },
    },
  });
  return {
    shield,
    count: () => forwarded,
    send: (url: string, init?: RequestInit) =>
      shield.handle(new Request(url, init), { tenant: "test" }),
  };
}

test("native SecLang blocks before origin and preserves normal traffic", async () => {
  const x = await engine(
    'SecRule ARGS "@contains UNION" "id:10001,phase:2,deny,t:none,status:406"',
  );
  assert.equal((await x.send("https://example.test/api?q=UNION")).status, 406);
  assert.equal(x.count(), 0);
  assert.equal((await x.send("https://example.test/api?q=normal")).status, 200);
  assert.equal(x.count(), 1);
});

test("native SecLang respects operator-controlled white list by rule ID", async () => {
  const x = await engine('SecRule ARGS "@contains UNION" "id:10001,phase:2,deny,t:none"', [
    { id: "exception", skip: ["rules"], ruleIds: ["10001"] },
  ]);
  assert.equal((await x.send("https://example.test/api?q=UNION")).status, 200);
});

test("response-body enforcement preserves bytes and holds capacity until the consumer finishes", async () => {
  let originBody = "safe response";
  const shield = await createShield({
    tenant: "test",
    service: "api",
    publicHosts: ["example.test"],
    routes: [{ business: "app", path: "/api", methods: ["GET"], authenticated: false }],
    secLang: 'SecRule RESPONSE_BODY "@contains secret" "id:10002,phase:4,deny"',
    maxConcurrentRequests: 1,
    origins: {
      app: {
        origin: "https://backend.test",
        allowedOrigins: ["https://backend.test"],
        originToken: "a-secret-long-enough-to-be-an-origin-token",
        fetch: async () => new Response(originBody),
      },
    },
  });
  const send = () => shield.handle(new Request("https://example.test/api"), { tenant: "test" });
  const first = await send();
  assert.equal(first.status, 200);
  assert.equal((await send()).status, 503);
  assert.equal(await first.text(), "safe response");
  originBody = "secret";
  assert.equal((await send()).status, 403);
  originBody = "safe again";
  const last = await send();
  assert.equal(last.status, 200);
  assert.equal(await last.text(), "safe again");
});

test("native SecLang rejects missing required primitive backends", async () => {
  await assert.rejects(
    engine('SecRule ARGS "@detectSQLi" "id:10001,phase:2,deny"'),
    /requires the libinjection primitive backend/,
  );
});
