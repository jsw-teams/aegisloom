import assert from "node:assert/strict";
import { test } from "node:test";
import { type AllowlistEntry, createShield } from "../../scr/runtime/index.js";

async function fixture(allowlist: AllowlistEntry[] = []) {
  let originHits = 0;
  const shield = await createShield({
    tenant: "testing",
    service: "api",
    publicHosts: ["testing.example"],
    secLang: 'SecRule ARGS:q "@streq attack" "id:100,deny"',
    allowlist,
    routes: [
      { business: "app", path: "/api", methods: ["GET"], authenticated: false, body: "none" },
    ],
    origins: {
      app: {
        origin: "https://origin.invalid",
        allowedOrigins: ["https://origin.invalid"],
        originToken: "allowlist-test-origin-token-long-enough",
        fetch: async () => {
          originHits++;
          return new Response("ok");
        },
      },
    },
  });
  const send = (identity?: string, verifiedClientIp?: string, q = "attack") =>
    shield.handle(new Request(`https://testing.example/api?q=${q}`), {
      tenant: "testing",
      ...(identity ? { identity } : {}),
      ...(verifiedClientIp ? { verifiedClientIp } : {}),
    });
  return { send, hits: () => originHits };
}
test("operator can globally bypass WAF rules when explicitly configured", async () => {
  const f = await fixture([
    { id: "owner-global", skip: ["rules"], reason: "explicit owner choice" },
  ]);
  assert.equal((await f.send()).status, 200);
  assert.equal(f.hits(), 1);
});
test("operator can exempt identity, CIDR, method and selected rules", async () => {
  const f = await fixture([
    {
      id: "false-positive",
      skip: ["rules"],
      ruleIds: ["100"],
      path: "/api",
      methods: ["GET"],
      identity: "trusted",
      cidrs: ["192.0.2.0/24"],
    },
  ]);
  assert.equal((await f.send("trusted", "192.0.2.8")).status, 200);
  assert.equal((await f.send("bad", "192.0.2.8")).status, 403);
  assert.equal((await f.send("trusted", "192.0.3.1")).status, 403);
});
test("operator can set expiry and expired entries stop matching", async () => {
  const f = await fixture([
    {
      id: "expired",
      skip: ["rules"],
      expiresAt: "2020-01-01T00:00:00Z",
    },
  ]);
  assert.equal((await f.send()).status, 403);
});
test("invalid CIDR is rejected; no trusted client-IP spoofing", async () => {
  await assert.rejects(fixture([{ id: "bad", skip: ["rules"], cidrs: ["not-an-ip"] }]), /CIDR/);
});
test("allowlist does not bypass route and identity security boundary", async () => {
  const shield = await createShield({
    tenant: "testing",
    service: "api",
    publicHosts: ["testing.example"],
    secLang: 'SecAction "id:101,phase:1,pass"',
    allowlist: [{ id: "global", skip: ["rules"] }],
    routes: [
      { business: "app", path: "/private", methods: ["GET"], authenticated: true, body: "none" },
    ],
    origins: {
      app: {
        origin: "https://origin.invalid",
        allowedOrigins: ["https://origin.invalid"],
        originToken: "allowlist-test-origin-token-long-enough",
        fetch: async () => new Response("ok"),
      },
    },
  });
  assert.equal(
    (await shield.handle(new Request("https://testing.example/private"), { tenant: "testing" }))
      .status,
    401,
  );
});
