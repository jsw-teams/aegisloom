import { digest, requireInteger, stableJson } from "../core/types.js";
import { loadPolicy, type Policy, policyVersion, type Rule } from "../rule-ir/index.js";
import { compileRule } from "./compile.js";
import {
  type Approval,
  type Capability,
  type CloudAdapter,
  type CloudPlan,
  type NativeGateway,
  type NativeRule,
  UnsupportedCapability,
} from "./types.js";

const snapshot = (rules: NativeRule[]) =>
  rules
    .map((r) => ({ name: r.name, payload: r.payload }))
    .sort((a, b) => a.name.localeCompare(b.name));
export class ManagedCloudAdapter implements CloudAdapter {
  constructor(
    private readonly cap: Capability,
    private readonly gateway: NativeGateway | undefined,
    private readonly tenant: string,
    private readonly service: string,
  ) {
    requireInteger(cap.maxRules, cap.management ? 1 : 0, 100000, "native rule quota");
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(tenant) || !/^[A-Za-z0-9_-]{1,64}$/.test(service))
      throw new Error("Invalid cloud tenant/service");
  }
  capabilities(): Capability {
    return structuredClone(this.cap);
  }
  compile(rule: Rule) {
    return compileRule(rule, this.cap);
  }
  private requireGateway(): NativeGateway {
    if (!this.cap.management || !this.gateway)
      throw new UnsupportedCapability(`${this.cap.provider} management unavailable/unconfigured`);
    return this.gateway;
  }
  private async namespace(): Promise<string> {
    return `shield-${(await digest(stableJson([this.tenant, this.service]))).slice(0, 16)}-`;
  }
  async readback(): Promise<NativeRule[]> {
    const result = await this.requireGateway().list();
    if (
      result.length > this.cap.maxRules ||
      new Set(result.map((r) => r.name)).size !== result.length
    )
      throw new Error("Provider response violates configured capacity/unique-name contract");
    return result;
  }
  async plan(source: Policy): Promise<CloudPlan> {
    const policy = loadPolicy(source);
    const gateway = this.requireGateway();
    const namespace = await this.namespace();
    const previous = await this.readback();
    const report = policy.rules
      .filter((r) => r.service === this.service && r.enabled)
      .map((r) => this.compile(r));
    const important = policy.rules.filter(
      (r) => r.service === this.service && r.enabled && r.placement === "edge-required",
    );
    if (important.some((r) => report.find((c) => c.ruleId === r.id)?.status !== "exact"))
      throw new Error("Required edge rule incompatible; deployment refused");
    const desired = previous.filter((r) => !r.name.startsWith(namespace));
    for (const compiled of report)
      if (compiled.payload) {
        const name = namespace + (await digest(compiled.ruleId)).slice(0, 20);
        const old = previous.find((r) => r.name === name);
        desired.push({ id: old?.id ?? "", name, payload: compiled.payload });
      }
    if (desired.length > this.cap.maxRules)
      throw new Error("Configured native rule capacity exceeded");
    const content = {
      provider: this.cap.provider,
      target: gateway.target,
      namespace,
      policy: await policyVersion(policy),
      baseHash: await digest(stableJson(snapshot(previous))),
      desired,
      report,
    };
    return { ...content, hash: await digest(stableJson(content)) };
  }
  async apply(plan: CloudPlan, approval: Approval): Promise<{ status: "confirmed"; hash: string }> {
    const gateway = this.requireGateway();
    const { hash, ...content } = plan;
    if (
      plan.target !== gateway.target ||
      plan.provider !== this.cap.provider ||
      plan.namespace !== (await this.namespace()) ||
      hash !== (await digest(stableJson(content))) ||
      approval.planHash !== hash ||
      !approval.approvedBy ||
      approval.expiresAt <= Date.now() ||
      approval.expiresAt > Date.now() + 86400000
    )
      throw new Error("Invalid, altered, expired or cross-target deployment approval");
    const previous = await this.readback();
    if ((await digest(stableJson(snapshot(previous)))) !== plan.baseHash)
      throw new Error("Configuration drift; regenerate and approve a new plan");
    if (plan.desired.length > this.cap.maxRules) throw new Error("Capacity exceeded");
    // Guard unowned records even if a caller hand-constructs and approves a plan.
    const unowned = snapshot(previous.filter((r) => !r.name.startsWith(plan.namespace)));
    if (
      stableJson(unowned) !==
      stableJson(snapshot(plan.desired.filter((r) => !r.name.startsWith(plan.namespace))))
    )
      throw new Error("Unowned native rules cannot be changed");
    await gateway.replace(plan.desired, previous);
    const current = await this.readback();
    if (stableJson(snapshot(current)) !== stableJson(snapshot(plan.desired)))
      throw new Error("Native readback differs; enforcement NOT confirmed");
    return { status: "confirmed", hash };
  }
  /** Returns a concrete removal plan. No external mutation occurs until approved apply(). */
  async revoke(ruleId: string): Promise<CloudPlan> {
    const gateway = this.requireGateway();
    const namespace = await this.namespace();
    const previous = await this.readback();
    const name = namespace + (await digest(ruleId)).slice(0, 20);
    const content = {
      provider: this.cap.provider,
      target: gateway.target,
      namespace,
      policy: "revoke",
      baseHash: await digest(stableJson(snapshot(previous))),
      desired: previous.filter((r) => r.name !== name),
      report: [],
    };
    return { ...content, hash: await digest(stableJson(content)) };
  }
  async reconcile(plan: CloudPlan): Promise<{ drift: boolean; observed: string }> {
    const rules = await this.readback();
    return {
      drift: stableJson(snapshot(rules)) !== stableJson(snapshot(plan.desired)),
      observed: await digest(stableJson(snapshot(rules))),
    };
  }
}
