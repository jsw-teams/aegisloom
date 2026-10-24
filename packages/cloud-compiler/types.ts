import type { Policy, Rule } from "../rule-ir/index.js";
export type Provider = "cloudflare" | "netlify" | "vercel" | "esa" | "edgeone";
export type Compatibility = "exact" | "runtime-only" | "partial" | "unsupported";
export interface Capability {
  provider: Provider;
  management: boolean;
  verifiedLive: false;
  maxRules: number;
  actions: string[];
  fields: string[];
  limitations: string[];
}
export interface CompiledRule {
  ruleId: string;
  status: Compatibility;
  errors: string[];
  payload?: Record<string, unknown>;
}
export interface NativeRule {
  id: string;
  name: string;
  payload: Record<string, unknown>;
}
export interface NativeGateway {
  readonly target: string;
  list(): Promise<NativeRule[]>;
  /** Idempotent desired-state reconciliation; preserve all unowned rules. */
  replace(rules: NativeRule[], previous: NativeRule[]): Promise<void>;
}
export interface CloudPlan {
  provider: Provider;
  target: string;
  namespace: string;
  policy: string;
  baseHash: string;
  desired: NativeRule[];
  report: CompiledRule[];
  hash: string;
}
export interface Approval {
  planHash: string;
  approvedBy: string;
  expiresAt: number;
}
export interface CloudAdapter {
  capabilities(): Capability;
  compile(rule: Rule): CompiledRule;
  plan(policy: Policy): Promise<CloudPlan>;
  apply(plan: CloudPlan, approval: Approval): Promise<{ status: "confirmed"; hash: string }>;
  readback(): Promise<NativeRule[]>;
  revoke(ruleId: string): Promise<CloudPlan>;
  reconcile(plan: CloudPlan): Promise<{ drift: boolean; observed: string }>;
}
export class UnsupportedCapability extends Error {
  constructor(message: string) {
    super(`unsupported: ${message}`);
    this.name = "UnsupportedCapability";
  }
}
