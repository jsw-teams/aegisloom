import assert from "node:assert/strict";
import { test } from "node:test";
import { MemoryDecisionStore } from "../packages/decision-cache/index.js";
import { createShield } from "../packages/runtime/index.js";

async function engine(
  source: string,
  allowlist: Array<{
    id: string;
    skip: ("rules" | "community")[];
    ruleIds?: string[];
  }> = [],
) {
  let forwarded = 0;
  const shield = await createShield({
    tenant: "test",
    service: "api",
    publicHosts: ["example.test"],
    routes: [{ path: "/api", methods: ["GET", "POST"], authenticated: false, body: "text" }],
    secLang: source,
    allowlist,
    decisions: new MemoryDecisionStore(),
    proxy: {
      origin: "https://backend.test",
      allowedOrigins: ["https://backend.test"],
      originToken: "a-secret-long-enough-to-be-an-origin-token",
      fetch: async () => {
        forwarded++;
        return new Response("origin ok");
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

test("native SecLang rejects unsupported directives and mutually exclusive legacy policy", async () => {
  await assert.rejects(
    engine('SecRule ARGS "@detectSQLi" "id:10001,phase:2,deny"'),
    /Unsupported operator/,
  );
  await assert.rejects(
    createShield({
      tenant: "test",
      service: "api",
      publicHosts: ["example.test"],
      routes: [],
      secLang: 'SecRule REQUEST_METHOD "@streq GET" "id:10001,phase:1,deny"',
      policy: { version: "1", rules: [] },
      decisions: new MemoryDecisionStore(),
      proxy: {
        origin: "https://backend.test",
        allowedOrigins: ["https://backend.test"],
        originToken: "a-secret-long-enough-to-be-an-origin-token",
      },
    }),
    /Exactly one/,
  );
});
