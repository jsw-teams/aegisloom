import assert from "node:assert/strict";
import { test } from "node:test";
import { context, fixture, request, token } from "./helpers.js";

const route = {
  business: "app",
  path: "/api",
  methods: ["GET", "HEAD", "POST"],
  authenticated: false,
  browserCache: { maxAgeSeconds: 120 },
};

test("browser freshness is bounded, credential-sensitive and never reuses a rule decision", async () => {
  const shield = await fixture({
    routes: [route],
    origins: {
      app: {
        origin: "https://origin.test",
        allowedOrigins: ["https://origin.test"],
        originToken: token,
        fetch: async () =>
          new Response("catalog", {
            headers: {
              "cache-control": "public, max-age=60",
              etag: '"catalog-v1"',
              vary: "Accept-Language",
              age: "5",
            },
          }),
      },
    },
  });
  try {
    for (let i = 0; i < 2; i++) {
      const response = await shield.handle(request(), context);
      assert.equal(await response.text(), "catalog");
      assert.equal(response.headers.get("cache-control"), "private, max-age=60, must-revalidate");
      assert.equal(response.headers.get("vary"), "Accept-Language, Cookie, Authorization");
      assert.equal(response.headers.get("etag"), '"catalog-v1"');
      assert.equal(response.headers.get("age"), "5");
    }
    assert.equal(shield.stats.originRequests, 2);
    const before = shield.stats.ruleEvaluations;
    const attack = await shield.handle(request("?q=attack"), context);
    assert.equal(attack.status, 403);
    assert.equal(attack.headers.get("cache-control"), "no-store");
    await attack.text();
    assert.ok(shield.stats.ruleEvaluations > before);
    assert.equal(shield.stats.originRequests, 2);
    for (const headers of [
      { cookie: "session=1" },
      { authorization: "Bearer user" },
      { "cache-control": "no-cache" },
      { "cache-control": "max-age=0" },
      { "cache-control": 'max-age="0"' },
      { "cache-control": 'no-cache="etag"' },
      { pragma: "no-cache" },
    ]) {
      const response = await shield.handle(request("", { headers }), context);
      assert.equal(response.headers.get("cache-control"), "no-store");
      await response.text();
    }
    for (const [method, identity] of [
      ["POST", undefined],
      ["GET", "verified-user"],
    ] as const) {
      const response = await shield.handle(
        request("", { method }),
        identity ? { ...context, identity } : context,
      );
      assert.equal(response.headers.get("cache-control"), "no-store");
      await response.text();
    }
  } finally {
    shield.dispose();
  }
});

test("origin privacy, cache ambiguity, error responses and cookies veto browser caching", async () => {
  for (const [headers, status] of [
    [{ "cache-control": "public, max-age=600" }, 200],
    [{ "cache-control": "max-age=60" }, 200],
    [{ "cache-control": "public, max-age=0" }, 200],
    [{ "cache-control": "public, max-age=60, no-store" }, 200],
    [{ "cache-control": 'public, max-age=60, private="user"' }, 200],
    [{ "cache-control": 'public, max-age=60, no-cache="etag"' }, 200],
    [{ "cache-control": "public, max-age=60, max-age=90" }, 200],
    [{ "cache-control": "public, max-age=60", "set-cookie": "user=1" }, 200],
    [{ "cache-control": "public, max-age=60", vary: "*" }, 200],
    [{ "cache-control": "public, max-age=60" }, 500],
  ] as const) {
    const shield = await fixture({
      routes: [route],
      origins: {
        app: {
          origin: "https://origin.test",
          allowedOrigins: ["https://origin.test"],
          originToken: token,
          fetch: async () => new Response("data", { status, headers }),
        },
      },
    });
    try {
      const response = await shield.handle(request(), context);
      assert.equal(
        response.headers.get("cache-control"),
        status === 200 && headers["cache-control"] === "public, max-age=600"
          ? "private, max-age=120, must-revalidate"
          : "no-store",
      );
      await response.text();
    } finally {
      shield.dispose();
    }
  }
  for (const browserCache of [
    { maxAgeSeconds: 0 },
    { maxAgeSeconds: 86401 },
    { maxAgeSeconds: 1.5 },
    { maxAgeSeconds: 60, unknown: true },
  ])
    await assert.rejects(fixture({ routes: [{ ...route, browserCache }] }), /cache/);
  await assert.rejects(fixture({ routes: [{ ...route, authenticated: true }] }), /anonymous/);
  await assert.rejects(fixture({ routes: [{ ...route, websocket: true }] }), /anonymous/);
});
