import { boundedJson } from "../core/remote.js";
import type { Fetch } from "../core/types.js";
import type { DecisionStore, SecurityDecision } from "./model.js";

/** Tenant credential binds the remote store; arbitrary caller tenants are rejected locally. */
export class HttpDecisionStore implements DecisionStore {
  private readonly endpoint: URL;
  constructor(
    endpoint: string,
    private readonly token: string,
    private readonly tenant: string,
    private readonly transport: Fetch = fetch,
    allowLoopbackHttp = false,
  ) {
    this.endpoint = new URL(endpoint);
    if (
      this.endpoint.protocol !== "https:" &&
      !(
        allowLoopbackHttp &&
        this.endpoint.protocol === "http:" &&
        ["127.0.0.1", "[::1]"].includes(this.endpoint.hostname)
      )
    )
      throw new Error("Control plane TLS required");
    if (
      this.endpoint.username ||
      this.endpoint.password ||
      this.endpoint.search ||
      this.endpoint.hash ||
      this.endpoint.pathname !== "/"
    )
      throw new Error("Control endpoint must be an origin");
    if (!/^[\x21-\x7e]{32,2048}$/.test(token))
      throw new Error("Control token must be 32..2048 visible ASCII characters");
  }
  private async call(tenant: string, path: string, method = "GET", body?: unknown): Promise<any> {
    if (tenant !== this.tenant) throw new Error("Cross-tenant store access rejected");
    const init: RequestInit = {
      method,
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
      headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
    };
    if (body !== undefined) init.body = JSON.stringify(body);
    const response = await this.transport(new URL(path, this.endpoint), init);
    if (!response.ok) throw new Error(`Decision API status ${response.status}`);
    return boundedJson(response);
  }
  async generation(tenant: string): Promise<number> {
    return (await this.call(tenant, "/v1/generation")).generation;
  }
  async get(tenant: string, key: string, _now: number): Promise<SecurityDecision | undefined> {
    return (
      (await this.call(tenant, `/v1/decisions?key=${encodeURIComponent(key)}`)).decision ??
      undefined
    );
  }
  async put(decision: SecurityDecision, expectedGeneration: number): Promise<boolean> {
    return (
      (await this.call(decision.tenant, "/v1/decisions", "PUT", { decision, expectedGeneration }))
        .applied === true
    );
  }
  async revoke(tenant: string, id: string, _now: number): Promise<number> {
    return (await this.call(tenant, "/v1/revoke", "POST", { id })).generation;
  }
  async list(tenant: string, _now: number): Promise<SecurityDecision[]> {
    return (await this.call(tenant, "/v1/decisions")).decisions;
  }
}
