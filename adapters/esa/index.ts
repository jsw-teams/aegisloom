import { createRequire } from "node:module";
import { ManagedCloudAdapter } from "../../packages/cloud-compiler/adapter.js";
import type { Capability, NativeGateway, NativeRule } from "../../packages/cloud-compiler/types.js";
import { stableJson } from "../../packages/core/types.js";

export function esaCapabilities(maxRules: number): Capability {
  return {
    provider: "esa",
    management: true,
    verifiedLive: false,
    maxRules,
    actions: ["block"],
    fields: ["method", "client.ip"],
    limitations: [
      "Official ESA 2024-09-10 SDK; pre-existing http_custom ruleset required",
      "Only siteVersion=0 supported; version-managed publication is unsupported",
      "Requires actual plan quota and a single configuration writer",
      "Readback does not prove every POP has converged",
    ],
  };
}
export interface EsaApi {
  list(args: Record<string, unknown>): Promise<any>;
  create(args: Record<string, unknown>): Promise<any>;
  update(args: Record<string, unknown>): Promise<any>;
  remove(args: Record<string, unknown>): Promise<any>;
}
export class EsaGateway implements NativeGateway {
  readonly target: string;
  constructor(
    private readonly api: EsaApi,
    private readonly siteId: number,
    private readonly rulesetId: number,
  ) {
    if (![siteId, rulesetId].every((n) => Number.isSafeInteger(n) && n > 0))
      throw new Error("Invalid ESA target IDs");
    this.target = `esa:${siteId}/${rulesetId}/0`;
  }
  async list(): Promise<NativeRule[]> {
    const result: NativeRule[] = [];
    for (let pageNumber = 1; pageNumber <= 100; pageNumber++) {
      const response = await this.api.list({
        siteId: this.siteId,
        rulesetId: this.rulesetId,
        siteVersion: 0,
        phase: "http_custom",
        pageNumber,
        pageSize: 100,
      });
      if (!Array.isArray(response.rules) || !Number.isSafeInteger(response.totalCount))
        throw new Error("Malformed ESA rule list");
      for (const r of response.rules) {
        if (r.rulesetId !== this.rulesetId || r.phase !== "http_custom")
          throw new Error("ESA rule target mismatch");
        result.push({
          id: String(r.id),
          name: r.config?.name ?? r.name,
          payload: {
            expression: r.config?.expression,
            action: r.config?.action ?? r.action,
            status: r.config?.status ?? r.status,
          },
        });
      }
      if (result.length >= response.totalCount) return result;
      if (!response.rules.length) throw new Error("Incomplete ESA pagination");
    }
    throw new Error("ESA pagination capacity exceeded");
  }
  async replace(desired: NativeRule[], previous: NativeRule[]): Promise<void> {
    for (const old of previous)
      if (!desired.some((r) => r.name === old.name))
        await this.api.remove({ siteId: this.siteId, siteVersion: 0, id: Number(old.id) });
    for (const rule of desired) {
      const old = previous.find((r) => r.name === rule.name);
      if (old && stableJson(old.payload) === stableJson(rule.payload)) continue;
      const config = { ...rule.payload, name: rule.name };
      if (old)
        await this.api.update({ siteId: this.siteId, siteVersion: 0, id: Number(old.id), config });
      else
        await this.api.create({
          siteId: this.siteId,
          siteVersion: 0,
          rulesetId: this.rulesetId,
          phase: "http_custom",
          config,
        });
    }
  }
}
/** No network is used until the gateway's management methods are called. */
export function createEsaSdkGateway(config: {
  accessKeyId: string;
  accessKeySecret: string;
  securityToken?: string;
  siteId: number;
  rulesetId: number;
  region: "cn-hangzhou" | "ap-southeast-1";
}) {
  const require = createRequire(import.meta.url);
  const sdk = require("@alicloud/esa20240910") as typeof import("@alicloud/esa20240910");
  const openapi = require("@alicloud/openapi-client") as typeof import("@alicloud/openapi-client");
  const client = new sdk.default(
    new openapi.Config({
      accessKeyId: config.accessKeyId,
      accessKeySecret: config.accessKeySecret,
      securityToken: config.securityToken,
      endpoint: `esa.${config.region}.aliyuncs.com`,
      connectTimeout: 5000,
      readTimeout: 10000,
    }),
  );
  return new EsaGateway(
    {
      list: async (args) => (await client.listWafRules(new sdk.ListWafRulesRequest(args))).body,
      create: async (args) => (await client.createWafRule(new sdk.CreateWafRuleRequest(args))).body,
      update: async (args) => (await client.updateWafRule(new sdk.UpdateWafRuleRequest(args))).body,
      remove: async (args) => (await client.deleteWafRule(new sdk.DeleteWafRuleRequest(args))).body,
    },
    config.siteId,
    config.rulesetId,
  );
}
export function createEsaAdapter(config: {
  tenant: string;
  service: string;
  maxRules: number;
  gateway?: NativeGateway;
}) {
  return new ManagedCloudAdapter(
    esaCapabilities(config.maxRules),
    config.gateway,
    config.tenant,
    config.service,
  );
}
