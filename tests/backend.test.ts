import assert from "node:assert/strict";
import { test } from "node:test";
import {
  type BackendPolicy,
  createBackendGuard,
  validateBackendPolicy,
} from "../packages/backend-security/index.js";

const token = "test-origin-secret-never-use-in-production";
const policy: BackendPolicy = {
  version: "1",
  tenant: "test",
  service: "api",
  hosts: ["origin.test"],
  sessionOrigins: ["https://origin.test", "https://public-api.test"],
  maxBodyBytes: 64,
  timeoutMs: 500,
  maxConcurrentRequests: 2,
  routes: [
    { path: "/public", methods: ["GET"], auth: "public", body: "none" },
    { path: "/private", methods: ["POST"], auth: "session", body: "json" },
    { path: "/token", methods: ["GET"], auth: "bearer", body: "none" },
  ],
};
const req = (path: string, headers: Record<string, string> = {}, body?: string) =>
  new Request(`https://origin.test${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "x-shield-origin-auth": token, ...headers },
    ...(body === undefined ? {} : { body }),
  });
async function fixture() {
  let reached = 0;
  const events: unknown[] = [];
  const guard = await createBackendGuard({
    policy,
    originTokens: [token],
    authenticate: async (r) =>
      r.headers.get("cookie") === "session=verified" ||
      r.headers.get("authorization") === "Bearer verified"
        ? { subject: "owner" }
        : undefined,
    authorize: async (_, __, r) => r.headers.get("x-owned") === "yes",
    verifyCsrf: async (r) => r.headers.get("x-csrf-token") === "verified-token",
    handle: async (r, c) => {
      reached++;
      assert.equal(r.headers.has("x-shield-origin-auth"), false);
      assert.equal(r.headers.has("x-forwarded-for"), false);
      return Response.json(
        { subject: c.identity?.subject ?? "public" },
        {
          headers: {
            "cache-control": "public, max-age=999",
            "x-shield-origin-auth": token,
            server: "private",
          },
        },
      );
    },
    event: (e) => events.push(e),
  });
  return { guard, events, reached: () => reached };
}
test("backend denies origin bypass and never treats forwarded identity claims as authentication", async () => {
  const f = await fixture();
  assert.equal(
    (await f.guard(req("/public", { "x-shield-origin-auth": "", "x-forwarded-for": "127.0.0.1" })))
      .status,
    403,
  );
  assert.equal(
    (await f.guard(req("/token", { "x-shield-identity": "owner", "x-owned": "yes" }))).status,
    401,
  );
  assert.equal((await f.guard(req("/token", { authorization: "Bearer verified" }))).status, 403);
  const allowed = await f.guard(
    req("/token", { authorization: "Bearer verified", "x-owned": "yes" }),
  );
  assert.equal(allowed.status, 200);
  assert.equal(allowed.headers.get("cache-control"), "no-store");
  assert.equal(allowed.headers.has("server"), false);
  assert.equal(allowed.headers.has("x-shield-origin-auth"), false);
  assert.equal(f.reached(), 1);
  assert.ok(!JSON.stringify(f.events).includes(token));
  assert.ok(!JSON.stringify(f.events).includes("owner"));
});
test("backend requires session authentication, ownership, same-origin and CSRF token independently", async () => {
  const f = await fixture();
  const headers = {
    cookie: "session=verified",
    "x-owned": "yes",
    "content-type": "application/json",
    origin: "https://origin.test",
    "x-csrf-token": "verified-token",
  };
  for (const mutation of [
    { cookie: "" },
    { "x-owned": "no" },
    { origin: "https://evil.test" },
    { "x-csrf-token": "" },
  ])
    assert.ok((await f.guard(req("/private", { ...headers, ...mutation }, "{}"))).status >= 400);
  assert.equal((await f.guard(req("/private", headers, "{}"))).status, 200);
  assert.equal(
    (await f.guard(req("/private", { ...headers, origin: "https://public-api.test" }, "{}")))
      .status,
    200,
  );
  assert.equal((await f.guard(req("/private", headers, '{"x":1,"x":2}'))).status, 400);
  assert.equal((await f.guard(req("/private", headers, "x".repeat(65)))).status, 413);
  assert.equal(f.reached(), 2);
});
test("backend startup refuses missing required verifiers and unknown or weakened policy properties", async () => {
  const base = { policy, originTokens: [token], handle: async () => Response.json({}) };
  await assert.rejects(createBackendGuard(base), /authentication/);
  await assert.rejects(
    createBackendGuard({
      ...base,
      authenticate: async () => undefined,
      authorize: async () => false,
    }),
    /CSRF/,
  );
  for (const invalid of [
    { ...policy, tenant: undefined },
    { ...policy, originAuth: false },
    { ...policy, maxBodyBytes: 999999999 },
    { ...policy, routes: [...policy.routes, policy.routes[0]] },
  ])
    assert.throws(() => validateBackendPolicy(invalid));
});
test("origin rotation accepts current and previous credentials; backend errors are redacted", async () => {
  const previous = "previous-origin-secret-never-use-in-production";
  const guard = await createBackendGuard({
    policy: { ...policy, routes: [policy.routes[0]!] },
    originTokens: [token, previous],
    handle: async () => {
      throw new Error(`internal-${token}`);
    },
  });
  for (const secret of [token, previous]) {
    const response = await guard(req("/public", { "x-shield-origin-auth": secret }));
    assert.equal(response.status, 503);
    assert.ok(!(await response.text()).includes(token));
  }
});
test("hung application retains concurrency slot after deadline instead of spawning unbounded work", async () => {
  let finish: ((r: Response) => void) | undefined;
  const guard = await createBackendGuard({
    policy: { ...policy, timeoutMs: 10, maxConcurrentRequests: 1, routes: [policy.routes[0]!] },
    originTokens: [token],
    handle: async () =>
      new Promise<Response>((resolve) => {
        finish = resolve;
      }),
  });
  assert.equal((await guard(req("/public"))).status, 504);
  assert.equal((await guard(req("/public"))).status, 503);
  finish!(Response.json({ done: true }));
  await new Promise((resolve) => setTimeout(resolve, 5));
});

test("JSON profile rejects insecure cookies and preserves separate secure session cookies", async () => {
  for (const secure of [false, true]) {
    const guard = await createBackendGuard({
      policy: { ...policy, routes: [policy.routes[0]!] },
      originTokens: [token],
      handle: async () =>
        Response.json(
          {},
          {
            headers: [
              ["set-cookie", secure ? "a=1; Secure; HttpOnly; SameSite=Lax" : "a=1"],
              ["set-cookie", "b=2; Secure; HttpOnly; SameSite=Strict"],
            ],
          },
        ),
    });
    const response = await guard(req("/public"));
    assert.equal(response.status, secure ? 200 : 502);
    assert.equal(response.headers.getSetCookie().length, secure ? 2 : 0);
  }
});
