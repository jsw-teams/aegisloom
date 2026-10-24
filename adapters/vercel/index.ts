import { ManagedCloudAdapter } from "../../packages/cloud-compiler/adapter.js";
import { CloudApiError, cloudJson } from "../../packages/cloud-compiler/http.js";
import type { Capability, NativeGateway, NativeRule } from "../../packages/cloud-compiler/types.js";
import { type Fetch, stableJson } from "../../packages/core/types.js";

export function vercelCapabilities(maxRules: number): Capability {
  return {
    provider: "vercel",
    management: true,
    verifiedLive: false,
    maxRules,
    actions: ["block"],
    fields: ["method", "client.ip"],
    limitations: [
      "Requires active firewall and exclusive project configuration writer",
      "Pending unrelated drafts cause publication refusal",
      "Explicit draft activation then active configuration readback",
      "Body/path/query and platform rate-limit equivalence not claimed",
    ],
  };
}
export class VercelGateway implements NativeGateway {
  readonly target: string;
  private readonly query: string;
  constructor(
    projectId: string,
    teamId: string,
    private readonly token: string,
    private readonly transport: Fetch = fetch,
  ) {
    if (![projectId, teamId].every((s) => /^[A-Za-z0-9_-]{1,128}$/.test(s)))
      throw new Error("Invalid Vercel target IDs");
    this.query = new URLSearchParams({ projectId, teamId }).toString();
    this.target = `vercel:${teamId}/${projectId}`;
  }
  private async call(path: string, method = "GET", body?: unknown) {
    const init: RequestInit = {
      method,
      headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
    };
    if (body !== undefined) init.body = JSON.stringify(body);
    return cloudJson(
      this.transport,
      `https://api.vercel.com/v1/security/firewall/config${path}?${this.query}`,
      init,
    );
  }
  private project(config: any): NativeRule[] {
    if (config.firewallEnabled !== true || !Array.isArray(config.rules))
      throw new Error("Vercel firewall inactive or malformed config");
    return config.rules.map((r: any) => ({
      id: r.id,
      name: r.name,
      payload: { active: r.active, conditionGroup: r.conditionGroup, action: r.action },
    }));
  }
  async list(): Promise<NativeRule[]> {
    return this.project(await this.call("/active"));
  }
  async replace(desired: NativeRule[], previous: NativeRule[]): Promise<void> {
    const active = await this.call("/active");
    try {
      const draft = await this.call("/draft");
      if (draft.version !== active.version)
        throw new Error("Unrelated Vercel draft present; refusing to activate it");
    } catch (error) {
      if (!(error instanceof CloudApiError && error.status === 404)) throw error;
    }
    let changed = false;
    for (const old of previous)
      if (!desired.some((r) => r.name === old.name)) {
        await this.call("", "PATCH", { action: "rules.remove", id: old.id });
        changed = true;
      }
    for (const rule of desired) {
      const old = previous.find((r) => r.name === rule.name);
      if (old && stableJson(old.payload) === stableJson(rule.payload)) continue;
      // The pinned official SDK's rules.update contract is a reorder operation.
      // Replace content through documented remove/insert operations instead.
      if (old) await this.call("", "PATCH", { action: "rules.remove", id: old.id });
      await this.call("", "PATCH", {
        action: "rules.insert",
        value: { ...rule.payload, name: rule.name },
      });
      changed = true;
    }
    if (changed) {
      const draft = await this.call("/draft");
      if (!Number.isSafeInteger(draft.version)) throw new Error("Missing Vercel draft version");
      await this.call(`/${draft.version}/activate`, "POST");
    }
  }
}
export function createVercelAdapter(config: {
  tenant: string;
  service: string;
  maxRules: number;
  gateway?: NativeGateway;
}) {
  return new ManagedCloudAdapter(
    vercelCapabilities(config.maxRules),
    config.gateway,
    config.tenant,
    config.service,
  );
}
