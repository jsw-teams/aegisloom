import type { SecurityDecision } from "../packages/decision-cache/index.js";
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
