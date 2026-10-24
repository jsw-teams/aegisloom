import assert from "node:assert/strict";
import { test } from "node:test";
import {
  LruTtl,
  MemoryDecisionStore,
  type SecurityDecision,
} from "../packages/decision-cache/index.js";

export function decision(overrides: Partial<SecurityDecision> = {}): SecurityDecision {
  return {
    id: "d-1",
    tenant: "t",
    key: "a".repeat(64),
    policy: "b".repeat(64),
    ruleId: "r",
    source: "rule",
    confidence: 0.9,
    evidenceHash: "a".repeat(64),
    firstSeen: 100,
    lastSeen: 100,
    expiresAt: 200,
    generation: 0,
    version: 1,
    revoked: false,
    cloud: "pending",
    ...overrides,
  };
}
test("LRU capacity, recency, TTL and zero capacity guard", () => {
  const cache = new LruTtl<number>(2);
  cache.set("a", 1, 10);
  cache.set("b", 2, 10);
  assert.equal(cache.get("a", 1), 1);
  cache.set("c", 3, 10);
  assert.equal(cache.get("b", 1), undefined);
  assert.equal(cache.get("a", 10), undefined);
  assert.equal(cache.size, 1);
  assert.throws(() => new LruTtl(0));
});
test("distributed CAS, expiry, revoke races and tenant isolation", async () => {
  const store = new MemoryDecisionStore(2);
  assert.equal(await store.put(decision(), 0), true);
  assert.equal(await store.put(decision(), 0), false);
  assert.equal((await store.get("t", "a".repeat(64), 150))?.id, "d-1");
  assert.equal(await store.get("other", "a".repeat(64), 150), undefined);
  assert.equal(await store.revoke("t", "d-1", 150), 1);
  assert.equal(await store.put(decision({ version: 99 }), 0), false);
  assert.equal(await store.get("t", "a".repeat(64), 150), undefined);
  assert.equal(await store.put(decision({ id: "fresh", generation: 1, version: 3 }), 1), true);
  assert.equal(await store.get("t", "a".repeat(64), 200), undefined);
});
test("unbounded attacker keys cannot grow store beyond capacity", async () => {
  const store = new MemoryDecisionStore(2);
  for (let i = 0; i < 100; i++) await store.put(decision({ key: String(i) }), 0);
  assert.equal((await store.list("t", 150)).length, 2);
});
