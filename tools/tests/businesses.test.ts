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

test("hostname and longest prefix select a fixed origin; concurrent request transports stay isolated", async () => {
  const native = await loadSecLangFile("rules/seclang-bundle.json");
  const calls: string[] = [];
  const origin = (name: string): ProxyOptions => ({
    origin: `https://${name}.example`,
    allowedOrigins: [`https://${name}.example`],
    originToken: `test-${name}-authentication-secret-`.repeat(2),
    fetch: async () => {
      throw Error("Per-request transport was not selected");
    },
  });
  const engine = await createShield({
    tenant: "test",
    service: "hosts",
    publicHosts: ["one.test", "two.test"],
    ...native,
    origins: { one: origin("one"), two: origin("two"), special: origin("special") },
    routes: [
      {
        host: "one.test",
        path: "/",
        prefix: true,
        business: "one",
        methods: ["GET"],
        authenticated: false,
      },
      {
        host: "two.test",
        path: "/",
        prefix: true,
        business: "two",
        methods: ["GET"],
        authenticated: false,
      },
      {
        host: "one.test",
        path: "/special/",
        prefix: true,
        business: "special",
        methods: ["GET"],
        authenticated: false,
      },
    ],
  });
  const dispatch = async (host: string, path: string, label: string) => {
    const originFetches = Object.fromEntries(
      ["one", "two", "special"].map((name) => [
        name,
        async (input: RequestInfo | URL, init?: RequestInit) => {
          await new Promise((resolve) => setTimeout(resolve, name === "one" ? 10 : 1));
          assert.equal(new URL(String(input)).hostname, `${name}.example`);
          assert.equal(
            new Headers(init?.headers).get("x-shield-origin-auth"),
            `test-${name}-authentication-secret-`.repeat(2),
          );
          calls.push(`${label}:${name}`);
          return new Response(`${label}:${name}`);
        },
      ]),
    );
    const response = await engine.handle(
      new Request(`https://${host}${path}`, {
        headers: {
          host,
          "user-agent": "Mozilla/5.0",
          "x-shield-origin-auth": "forged-key",
          "x-forwarded-host": "attacker.example",
        },
      }),
      { tenant: "test", verifiedClientIp: "192.0.2.20", httpProtocol: "HTTP/1.1" },
      undefined,
      { originFetches },
    );
    return { status: response.status, body: await response.text() };
  };
  try {
    const replies = await Promise.all([
      dispatch("one.test", "/products", "first"),
      dispatch("two.test", "/products", "second"),
      dispatch("one.test", "/special/products", "third"),
    ]);
    assert.deepEqual(
      replies.map((r) => r.body),
      ["first:one", "second:two", "third:special"],
    );
    assert.equal(calls.length, 3);
    assert.equal(
      (
        await dispatch(
          "two.test",
          "/products?q=1%20UNION%20SELECT%20password%20FROM%20users",
          "blocked",
        )
      ).status,
      403,
    );
    assert.equal(calls.length, 3);
  } finally {
    engine.dispose();
  }
});
