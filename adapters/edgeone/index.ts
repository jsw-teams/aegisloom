import { ManagedCloudAdapter } from "../../packages/cloud-compiler/adapter.js";
import { cloudJson } from "../../packages/cloud-compiler/http.js";
import type { Capability, NativeGateway, NativeRule } from "../../packages/cloud-compiler/types.js";
import { type Fetch, stableJson } from "../../packages/core/types.js";
import { signTc3 } from "./sign.js";

export function edgeoneCapabilities(maxRules: number): Capability {
  return {
    provider: "edgeone",
    management: true,
    verifiedLive: false,
    maxRules,
    actions: ["block"],
    fields: ["method", "client.ip"],
    limitations: [
      "Official teo 2022-09-01 API with SDK-verified TC3 signing; assigned security template required",
      "CustomRules is replaced as a whole; requires a single configuration writer",
      "Unowned rules are preserved with their complete provider payload",
      "Template binding and POP propagation require operator verification",
    ],
  };
}
export interface EdgeOneApi {
  describe(args: any): Promise<any>;
  modify(args: any): Promise<any>;
}
export class EdgeOneGateway implements NativeGateway {
  readonly target: string;
  constructor(
    private readonly api: EdgeOneApi,
    private readonly zoneId: string,
    private readonly templateId: string,
    endpoint = "offline-injected-api",
  ) {
    if (![zoneId, templateId].every((s) => /^[a-zA-Z0-9_-]{1,128}$/.test(s)))
      throw new Error("Invalid EdgeOne target IDs");
    this.target = `edgeone:${endpoint}:${zoneId}/${templateId}`;
  }
  private args() {
    return { ZoneId: this.zoneId, Entity: "Template", TemplateId: this.templateId };
  }
  async list(): Promise<NativeRule[]> {
    const response = await this.api.describe(this.args());
    const rules = response.SecurityPolicy?.CustomRules?.Rules;
    if (!Array.isArray(rules))
      throw new Error("Missing EdgeOne CustomRules; refusing unknown policy state");
    return rules.map((r: any) => {
      const { Id, Name, ...payload } = r;
      return { id: Id ?? "", name: Name, payload };
    });
  }
  async replace(desired: NativeRule[], previous: NativeRule[]): Promise<void> {
    if (stableJson(desired) === stableJson(previous)) return;
    await this.api.modify({
      ...this.args(),
      SecurityConfig: {},
      SecurityPolicy: {
        CustomRules: {
          Rules: desired.map((r) => ({
            ...r.payload,
            Name: r.name,
            ...(r.id ? { Id: r.id } : {}),
          })),
        },
      },
    });
  }
}
export function createEdgeOneGateway(config: {
  secretId: string;
  secretKey: string;
  token?: string;
  zoneId: string;
  templateId: string;
  endpoint: "teo.tencentcloudapi.com" | "teo.intl.tencentcloudapi.com";
  fetch?: Fetch;
}) {
  if (!["teo.tencentcloudapi.com", "teo.intl.tencentcloudapi.com"].includes(config.endpoint))
    throw new Error("Invalid EdgeOne endpoint");
  const call = async (action: string, args: Record<string, unknown>) => {
    const timestamp = Math.floor(Date.now() / 1000);
    const body = JSON.stringify(args);
    const authorization = await signTc3({
      host: config.endpoint,
      service: "teo",
      body,
      timestamp,
      secretId: config.secretId,
      secretKey: config.secretKey,
    });
    const headers: Record<string, string> = {
      authorization,
      "content-type": "application/json; charset=utf-8",
      "x-tc-action": action,
      "x-tc-version": "2022-09-01",
      "x-tc-timestamp": String(timestamp),
    };
    if (config.token) headers["x-tc-token"] = config.token;
    const result = await cloudJson(config.fetch ?? fetch, `https://${config.endpoint}/`, {
      method: "POST",
      headers,
      body,
    });
    if (!result.Response || result.Response.Error)
      throw new Error("EdgeOne API rejected operation; sensitive response omitted");
    return result.Response;
  };
  return new EdgeOneGateway(
    {
      describe: (args) => call("DescribeSecurityPolicy", args),
      modify: (args) => call("ModifySecurityPolicy", args),
    },
    config.zoneId,
    config.templateId,
    config.endpoint,
  );
}
export function createEdgeOneAdapter(config: {
  tenant: string;
  service: string;
  maxRules: number;
  gateway?: NativeGateway;
}) {
  return new ManagedCloudAdapter(
    edgeoneCapabilities(config.maxRules),
    config.gateway,
    config.tenant,
    config.service,
  );
}
