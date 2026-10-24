import assert from "node:assert/strict";
import { test } from "node:test";
import { compileExpression } from "../packages/core/matcher.js";
import { boundedJson } from "../packages/core/remote.js";
import { MemoryDecisionStore } from "../packages/decision-cache/index.js";
import { loadPolicy } from "../packages/rule-ir/index.js";
import { decision } from "./decision-fixture.js";
import { attackRule, context, fixture, request } from "./helpers.js";

test("remote body limits apply before allocation and stalled reads are cancelled", async () => {
  await assert.rejects(boundedJson(new Response("x".repeat(100)), 10), /limit/);
  let cancelled = false;
  const response = new Response(
    new ReadableStream({
      cancel() {
        cancelled = true;
      },
    }),
  );
  await assert.rejects(boundedJson(response, 10, 10), /deadline/);
  assert.equal(cancelled, true);
});
test("RE2 nested quantifiers do not backtrack exponentially on bounded attack input", () => {
  const match = compileExpression({ field: "body", op: "regex", value: "(a+)+$" });
  const req = request();
  const start = performance.now();
  assert.equal(
    match({
      request: req,
      url: new URL(req.url),
      path: "/api",
      bodyText: `${"a".repeat(20000)}!`,
      context,
    }),
    false,
  );
  assert.ok(performance.now() - start < 3000);
});
test("weak signal correlation accumulates scores without mutating caller identity context", async () => {
  const rule = (id: string, priority: number) => ({
    ...attackRule,
    id,
    priority,
    when: { field: "path", op: "eq", value: "/api" },
    then: { action: "detect", score: 30 },
    cache: { enabled: false, ttl: "1m" },
  });
  const f = await fixture({
    policy: loadPolicy({
      version: "1",
      rules: [
        rule("weak-a", 1),
        rule("weak-b", 2),
        { ...attackRule, priority: 3, when: { field: "risk.score", op: "range", min: 60 } },
      ],
    }),
  });
  const ctx = { ...context, riskScore: 0 };
  assert.equal((await f.handle(request(), ctx)).status, 403);
  assert.equal(ctx.riskScore, 0);
  assert.equal(f.events.filter((e) => e.kind === "detect").length, 2);
});
test("decision lifetime can be renewed only after expiry or a fresh generation", async () => {
  const store = new MemoryDecisionStore();
  await store.put(decision(), 0);
  assert.equal(
    await store.put(decision({ firstSeen: 201, lastSeen: 201, expiresAt: 300 }), 0),
    true,
  );
  await store.revoke("t", "d-1", 220);
  assert.equal(
    await store.put(decision({ generation: 1, firstSeen: 221, lastSeen: 221, expiresAt: 400 }), 1),
    true,
  );
});
