import assert from "node:assert/strict";
import { test } from "node:test";
import { MemoryDecisionStore } from "../packages/decision-cache/index.js";
import { loadPolicy } from "../packages/rule-ir/index.js";
import { attackRule, context, fixture, request } from "./helpers.js";

test("first attack rule -> L1 -> second instance L2 -> revocation invalidates old caches", async () => {
  const decisions = new MemoryDecisionStore();
  const a = await fixture({ decisions });
  const b = await fixture({ decisions });
  assert.equal((await a.handle(request("?q=attack"), context)).status, 403);
  assert.equal(a.events.at(-1)?.source, "rule");
  const initialDecision = (await decisions.list(context.tenant, Date.now()))[0]!;
  assert.equal(initialDecision.confidence, 0.5);
  assert.equal(initialDecision.cloud, "unsupported");
  assert.equal((await a.handle(request("?q=attack"), context)).status, 403);
  assert.equal(a.events.at(-1)?.source, "l1");
  assert.equal(a.stats.ruleEvaluations, 1);
  await b.handle(request("?q=attack"), context);
  assert.equal(b.events.at(-1)?.source, "l2");
  const id = a.events.at(-1)?.decisionId;
  assert.ok(id);
  await decisions.revoke(context.tenant, id, Date.now());
  await a.handle(request("?q=attack"), context);
  assert.equal(a.events.at(-1)?.source, "rule"); // Re-evaluation is required; active rule still blocks.
  assert.equal(a.forwarded.length + b.forwarded.length, 0);
});
test("legitimate request proxies with origin auth and strips forged forwarding metadata", async () => {
  const f = await fixture();
  const result = await f.handle(
    request("?q=hello", {
      headers: {
        "x-forwarded-for": "1.1.1.1",
        "x-shield-origin-auth": "forged",
        authorization: "Bearer application-token",
      },
    }),
    context,
  );
  assert.equal(result.status, 200);
  assert.deepEqual(await result.json(), { ok: true });
  assert.equal(f.forwarded[0]?.url, "https://origin.test/api?q=hello");
  const headers = new Headers(f.forwarded[0]?.init?.headers);
  assert.equal(headers.has("x-forwarded-for"), false);
  assert.equal(headers.get("authorization"), "Bearer application-token");
  assert.notEqual(headers.get("x-shield-origin-auth"), "forged");
});
test("route and identity enforcement occurs before caching or origin", async () => {
  const f = await fixture();
  assert.equal((await f.handle(new Request("https://api.test/unknown"), context)).status, 404);
  assert.equal((await f.handle(request("", { method: "DELETE" }), context)).status, 405);
  assert.equal((await f.handle(new Request("https://api.test/private"), context)).status, 401);
  assert.equal((await f.handle(request(), { tenant: "other" })).status, 403);
  assert.equal(f.forwarded.length, 0);
});
test("body rule uses strict JSON pointer; detect rules continue to proxy", async () => {
  const f = await fixture({
    policy: loadPolicy({
      version: "1",
      rules: [
        {
          ...attackRule,
          id: "detection",
          cache: { enabled: false, ttl: "1m" },
          when: { field: "path", op: "eq", value: "/api" },
          then: { action: "detect" },
        },
        {
          ...attackRule,
          id: "body",
          priority: 20,
          phase: "request-body",
          when: { field: "body", key: "/command", op: "eq", value: "attack" },
        },
      ],
    }),
  });
  assert.equal(
    (
      await f.handle(
        request("", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: '{"command":"attack"}',
        }),
        context,
      )
    ).status,
    403,
  );
  assert.equal(
    (
      await f.handle(
        request("", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: '{"command":"safe"}',
        }),
        context,
      )
    ).status,
    200,
  );
  assert.ok(f.events.some((e) => e.kind === "detect"));
});
test("TTL expiry and rule expiry are enforced, cached blocks cannot outlive rules", async () => {
  let now = 1000;
  const f = await fixture({
    now: () => now,
    policy: loadPolicy({
      version: "1",
      rules: [{ ...attackRule, expiresAt: new Date(2000).toISOString() }],
    }),
  });
  assert.equal((await f.handle(request("?q=attack"), context)).status, 403);
  now = 2001;
  assert.equal((await f.handle(request("?q=attack"), context)).status, 200);
});
test("rate limits use verified identity, penalties and bounded state", async () => {
  let now = 0;
  const f = await fixture({
    now: () => now,
    rateCapacity: 1,
    policy: loadPolicy({
      version: "1",
      rules: [
        {
          ...attackRule,
          when: {
            path: "/api",
            requests: { moreThan: 2, within: "1m", groupBy: "verifiedClientIp" },
          },
          then: { action: "rate-limit", duration: "1m" },
          cache: { enabled: false, ttl: "1m" },
        },
      ],
    }),
  });
  assert.equal((await f.handle(request(), context)).status, 200);
  assert.equal((await f.handle(request(), context)).status, 200);
  assert.equal((await f.handle(request(), context)).status, 429);
  assert.equal(
    (await f.handle(request(), { tenant: context.tenant, verifiedClientIp: "192.0.2.2" })).status,
    503,
  );
  now = 61000;
  assert.equal((await f.handle(request(), context)).status, 200);
});
test("explicit closed mode rejects storage outages; default fallback still evaluates all rules", async () => {
  const decisions = new MemoryDecisionStore();
  decisions.generation = async () => {
    throw new Error("offline");
  };
  const closed = await fixture({ decisions, storageFailure: "closed" });
  assert.equal((await closed.handle(request(), context)).status, 503);
  const evaluate = await fixture({ decisions, storageFailure: "evaluate-rules" });
  assert.equal((await evaluate.handle(request("?q=attack"), context)).status, 403);
  assert.equal((await evaluate.handle(request(), context)).status, 200);
});

test("trace IDs do not defeat caches unless the policy actually matches that header", async () => {
  const f = await fixture();
  await f.handle(request("?q=attack", { headers: { "cf-ray": "one" } }), context);
  await f.handle(request("?q=attack", { headers: { "cf-ray": "two" } }), context);
  assert.equal(f.stats.l1Hits, 1);
  const observed = await fixture({
    policy: loadPolicy({
      version: "1",
      rules: [
        {
          ...attackRule,
          when: { field: "header", key: "CF-Ray", op: "eq", value: "one" },
        },
      ],
    }),
  });
  assert.equal(
    (await observed.handle(request("", { headers: { "cf-ray": "one" } }), context)).status,
    403,
  );
  const normal = await observed.handle(request("", { headers: { "cf-ray": "two" } }), context);
  assert.equal(normal.status, 200);
  await normal.body?.cancel();
});

test("services sharing a tenant and complete policy cannot consume each other's cached blocks", async () => {
  const decisions = new MemoryDecisionStore();
  const protectedService = await fixture({ decisions });
  const otherService = await fixture({ decisions, service: "other-service" });
  assert.equal((await protectedService.handle(request("?q=attack"), context)).status, 403);
  const result = await otherService.handle(request("?q=attack"), context);
  assert.equal(result.status, 200);
  assert.equal(otherService.stats.l2Hits, 0);
  await result.body?.cancel();
});
