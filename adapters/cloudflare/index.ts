import { ManagedCloudAdapter } from "../../packages/cloud-compiler/adapter.js";
import { cloudJson } from "../../packages/cloud-compiler/http.js";
import type { Capability, NativeGateway, NativeRule } from "../../packages/cloud-compiler/types.js";
import type { Fetch } from "../../packages/core/types.js";

export function cloudflareCapabilities(maxRules: number, enterpriseLog = false): Capability {
  return {
    provider: "cloudflare",
    management: true,
    verifiedLive: false,
    maxRules,
    actions: enterpriseLog ? ["block", "detect"] : ["block"],
    fields: ["method", "client.ip"],
    limitations: [
      "Operator supplies actual zone quota; no plan entitlement assumed",
      "Use an existing http_request_firewall_custom entry-point ruleset",
      "Body/path/query/header equivalence not implemented; remains runtime-only",
      "API readback confirms configuration, not global POP propagation",
    ],
  };
}
export class CloudflareGateway implements NativeGateway {
  readonly target: string;
  private readonly base: string;
  constructor(
    zoneId: string,
    rulesetId: string,
    private readonly token: string,
    private readonly transport: Fetch = fetch,
  ) {
    if (![zoneId, rulesetId].every((s) => /^[a-f0-9]{32}$/.test(s)))
      throw new Error("Cloudflare IDs must be 32 hex characters");
    this.base = `https://api.cloudflare.com/client/v4/zones/${zoneId}/rulesets/${rulesetId}`;
    this.target = this.base;
  }
  private async call(path = "", method = "GET", body?: unknown) {
    const init: RequestInit = {
      method,
      headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
    };
    if (body !== undefined) init.body = JSON.stringify(body);
    const response = await cloudJson(this.transport, this.base + path, init);
    if (response.success !== true) throw new Error("Cloudflare rejected management operation");
    return response.result;
  }
  async list(): Promise<NativeRule[]> {
    const result = await this.call();
    if (result.phase !== "http_request_firewall_custom" || !Array.isArray(result.rules))
      throw new Error("Wrong Cloudflare ruleset phase or malformed response");
    return result.rules.map((r: any) => ({
      id: r.id,
      name: r.ref ?? r.id,
      payload: {
        expression: r.expression,
        action: r.action,
        enabled: r.enabled !== false,
        ...(r.action_parameters ? { action_parameters: r.action_parameters } : {}),
      },
    }));
  }
  async replace(desired: NativeRule[], previous: NativeRule[]): Promise<void> {
    // Individual rule operations preserve unrelated platform metadata and managed features.
    for (const old of previous)
      if (!desired.some((r) => r.name === old.name))
        await this.call(`/rules/${encodeURIComponent(old.id)}`, "DELETE");
    for (const rule of desired) {
      const old = previous.find((r) => r.name === rule.name);
      if (old && JSON.stringify(old.payload) === JSON.stringify(rule.payload)) continue;
      await this.call(
        old ? `/rules/${encodeURIComponent(old.id)}` : "/rules",
        old ? "PATCH" : "POST",
        { ...rule.payload, ref: rule.name, description: rule.name },
      );
    }
  }
}
export function createCloudflareAdapter(config: {
  tenant: string;
  service: string;
  maxRules: number;
  gateway?: NativeGateway;
  enterpriseLog?: boolean;
}) {
  return new ManagedCloudAdapter(
    cloudflareCapabilities(config.maxRules, config.enterpriseLog),
    config.gateway,
    config.tenant,
    config.service,
  );
}
