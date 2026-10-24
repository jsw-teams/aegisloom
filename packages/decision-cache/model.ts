export interface SecurityDecision {
  id: string;
  tenant: string;
  key: string;
  policy: string;
  ruleId: string;
  source: "rule" | "operator" | "community";
  confidence: number;
  evidenceHash: string;
  firstSeen: number;
  lastSeen: number;
  expiresAt: number;
  generation: number;
  version: number;
  revoked: boolean;
  cloud: "pending" | "confirmed" | "unsupported" | "revoked";
}

/** Implementations must be linearizable per tenant. Eventual KV alone cannot satisfy this contract. */
export interface DecisionStore {
  generation(tenant: string): Promise<number>;
  get(tenant: string, key: string, now: number): Promise<SecurityDecision | undefined>;
  put(decision: SecurityDecision, expectedGeneration: number): Promise<boolean>;
  revoke(tenant: string, id: string, now: number): Promise<number>;
  list(tenant: string, now: number): Promise<SecurityDecision[]>;
}
