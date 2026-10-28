import assert from "node:assert/strict";
import { test } from "node:test";
import { createShield, type ProxyOptions } from "../../scr/runtime/index.js";
import { loadSecLangFile } from "../../scr/seclang/node.js";

// Transport spies observe real proxy routing; every decision is made by the complete CRS VM.
test("named function, VPS and CNAME businesses share full request/response inspection and never select origins from client input", async () => {
  const native = await loadSecLangFile("rules/seclang-bundle.json");
  const calls: { business: string; url: string }[] = [];
  const origins: Record<string, ProxyOptions> = {};
  for (const [business, origin] of Object.entries({
    shop: "https://shop.origin.internal",
    orders: "https://192.0.2.10",
    search: "https://lb.search.example",
  })) {
    origins[business] = {
      origin,
      allowedOrigins: [origin],
      originToken: `test-${business}-origin-authentication-token-long-enough`,
      fetch: async (input, init) => {
        const url = String(input);
        calls.push({ business, url });
        assert.equal(
          new Headers(init?.headers).get("x-shield-origin-auth"),
          `test-${business}-origin-authentication-token-long-enough`,
        );
        return new Response(
          new URL(url).searchParams.has("leak")
            ? "<title>=[ 1n73ct10n privat shell ]=</title>"
            : business,
          { headers: { "content-type": "text/html" } },
        );
      },
    };
  }
  const config = {
    tenant: "test",
    service: "multi",
    publicHosts: ["api.test"],
    ...native,
    routes: Object.keys(origins).map((business) => ({
      business,
      path: `/${business}`,
      methods: ["GET"],
      authenticated: false,
    })),
    origins,
  };
  const shield = await createShield(config);
  const send = (path: string) =>
    shield.handle(
      new Request(`https://api.test${path}`, {
        headers: { host: "api.test", "user-agent": "Mozilla/5.0", accept: "text/html" },
      }),
      { tenant: "test", verifiedClientIp: "192.0.2.1", httpProtocol: "HTTP/1.1" },
    );
  try {
    // Mutating caller-owned routing after compilation cannot redirect traffic.
    config.routes[0]!.business = "orders";
    for (const [index, business] of ["shop", "orders", "search"].entries()) {
      const normal = await send(`/${business}?origin=https://attacker.example`);
      assert.equal(normal.status, 200);
      assert.equal(await normal.text(), business);
      assert.equal(calls.at(-1)!.business, business);
      assert.equal(new URL(calls.at(-1)!.url).origin, origins[business]!.origin);
      const before = calls.length;
      const attack = await send(`/${business}?q=1%20UNION%20SELECT%20password%20FROM%20users`);
      assert.equal(attack.status, 403);
      await attack.text();
      assert.equal(calls.length, before);
      const leak = await send(`/${business}?leak=yes`);
      assert.equal(leak.status, 403);
      await leak.text();
      assert.equal(calls.length, (index + 1) * 2);
    }
    const unknown = await send("/missing");
    assert.equal(unknown.status, 404);
    await unknown.text();
    assert.equal(calls.length, 6);
  } finally {
    shield.dispose();
  }
  await assert.rejects(
    createShield({
      ...config,
      routes: [{ path: "/bad", business: "missing", methods: ["GET"], authenticated: false }],
    }),
    /configured business/,
  );
});
