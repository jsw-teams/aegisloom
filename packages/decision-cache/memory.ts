import { requireInteger } from "../core/types.js";
import type { DecisionStore, SecurityDecision } from "./model.js";

/** Executable L2/reference authority; NOT persistent or distributed outside a shared process. */
export class MemoryDecisionStore implements DecisionStore {
  private readonly tenants = new Map<
    string,
    { generation: number; decisions: Map<string, SecurityDecision> }
  >();
  constructor(
    private readonly maxDecisions = 10000,
    private readonly maxTenants = 100,
  ) {
    requireInteger(maxDecisions, 1, 1000000, "decision capacity");
    requireInteger(maxTenants, 1, 10000, "tenant capacity");
  }
  private state(tenant: string) {
    let state = this.tenants.get(tenant);
    if (!state) {
      if (this.tenants.size >= this.maxTenants) throw new Error("Tenant capacity exceeded");
      state = { generation: 0, decisions: new Map<string, SecurityDecision>() };
      this.tenants.set(tenant, state);
    }
    return state;
  }
  async generation(tenant: string): Promise<number> {
    return this.state(tenant).generation;
  }
  async get(tenant: string, key: string, now: number): Promise<SecurityDecision | undefined> {
    const state = this.state(tenant);
    const d = state.decisions.get(key);
    return d && !d.revoked && d.expiresAt > now && d.generation === state.generation
      ? structuredClone(d)
      : undefined;
  }
  async put(d: SecurityDecision, expected: number): Promise<boolean> {
    const state = this.state(d.tenant);
    if (state.generation !== expected || d.generation !== expected || d.revoked) return false;
    const previous = state.decisions.get(d.key);
    if (
      previous &&
      previous.generation === expected &&
      previous.expiresAt > d.firstSeen &&
      previous.version >= d.version
    )
      return false;
    if (!previous && state.decisions.size >= this.maxDecisions) {
      for (const [k, value] of state.decisions)
        if (value.expiresAt <= d.firstSeen || value.generation !== expected)
          state.decisions.delete(k);
      if (state.decisions.size >= this.maxDecisions) return false;
    }
    state.decisions.set(d.key, structuredClone(d));
    return true;
  }
  async revoke(tenant: string, id: string, now: number): Promise<number> {
    const state = this.state(tenant);
    for (const d of state.decisions.values())
      if (d.id === id) {
        d.revoked = true;
        d.lastSeen = now;
        d.version++;
        d.cloud = "revoked";
      }
    // Global tenant epoch invalidates all old decisions, including in-flight writes and unknown IDs.
    state.generation++;
    return state.generation;
  }
  async list(tenant: string, now: number): Promise<SecurityDecision[]> {
    const state = this.state(tenant);
    return [...state.decisions.values()]
      .filter((d) => !d.revoked && d.expiresAt > now && d.generation === state.generation)
      .map((d) => structuredClone(d));
  }
}
