import { digest } from "../core/types.js";
import { loadPolicy, type Rule } from "../rule-ir/index.js";

export type RolloutStage = "proposed" | "verified" | "shadow" | "canary" | "deployed" | "revoked";
export class RuleRollout {
  private stage: RolloutStage = "proposed";
  private normals = 0;
  private attacks = 0;
  private falsePositives = 0;
  private misses = 0;
  private percent = 0;
  readonly audit: { at: number; stage: RolloutStage; reason: string }[] = [];
  private readonly rule: Rule;
  constructor(
    source: Rule,
    private readonly minimumNormal = 100,
    private readonly minimumAttack = 5,
  ) {
    this.rule = loadPolicy({ version: "1", rules: [source] }).rules[0]!;
    if (["challenge", "rate-limit"].includes(this.rule.then.action) || this.rule.requests)
      throw new Error("Adaptive rollout supports stateless block/detect candidates only");
  }
  private change(stage: RolloutStage, reason: string): void {
    if (this.audit.length >= 1000) throw new Error("Rollout audit capacity reached");
    this.stage = stage;
    this.audit.push({ at: Date.now(), stage, reason });
  }
  /** Labels must come from a trusted independent regression/review process. */
  record(attack: boolean, matched: boolean): void {
    if (this.stage === "revoked") throw new Error("Rollout revoked");
    if (attack) {
      this.attacks++;
      if (!matched) this.misses++;
    } else {
      this.normals++;
      if (matched) this.falsePositives++;
    }
    if (["canary", "deployed"].includes(this.stage) && this.falsePositives > 0)
      this.change("revoked", "Automatic rollback: confirmed false positive");
  }
  private sufficient(): boolean {
    return (
      this.normals >= this.minimumNormal &&
      this.attacks >= this.minimumAttack &&
      this.falsePositives === 0 &&
      this.misses === 0
    );
  }
  verify(): void {
    if (this.stage !== "proposed" || !this.sufficient())
      throw new Error("Insufficient independent verification");
    this.change("verified", "Regression gates passed");
  }
  shadow(): void {
    if (this.stage !== "verified") throw new Error("Verify before shadow");
    this.normals = 0;
    this.attacks = 0;
    this.change("shadow", "Observe without enforcing");
  }
  canary(percent: number): void {
    if (
      this.stage !== "shadow" ||
      !this.sufficient() ||
      !Number.isInteger(percent) ||
      percent < 1 ||
      percent > 25
    )
      throw new Error("Shadow gate or canary percentage invalid");
    this.percent = percent;
    this.normals = 0;
    this.attacks = 0;
    this.change("canary", "Explicit canary activation");
  }
  deploy(): void {
    if (this.stage !== "canary" || !this.sufficient()) throw new Error("Canary gate not passed");
    this.change("deployed", "Explicit rollout activation");
  }
  revoke(reason: string): void {
    this.change("revoked", reason);
  }
  async shouldEnforce(trustedIdentity: string): Promise<boolean> {
    if (this.stage === "deployed") return true;
    if (this.stage !== "canary") return false;
    const bucket = Number.parseInt((await digest(trustedIdentity)).slice(0, 8), 16) % 100;
    return bucket < this.percent;
  }
  snapshot() {
    return {
      stage: this.stage,
      rule: structuredClone(this.rule),
      normals: this.normals,
      attacks: this.attacks,
      falsePositives: this.falsePositives,
      misses: this.misses,
    };
  }
}
export function anomalyCandidate(service: string, path: string, method: string): Rule {
  return loadPolicy({
    version: "1",
    rules: [
      {
        id: "adaptive-anomaly",
        name: "Explainable anomaly candidate (shadow first)",
        service,
        when: {
          all: [
            { field: "path", op: "eq", value: path },
            { field: "method", op: "eq", value: method },
            { field: "risk.score", op: "range", min: 50 },
          ],
        },
        then: { action: "detect" },
        cache: { enabled: false, ttl: "1m" },
      },
    ],
  }).rules[0]!;
}
