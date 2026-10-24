import { canonicalPath } from "../http-boundary/index.js";
import type { Anomaly, LearningModel, Observation, RouteBaseline } from "./types.js";

const routeKey = (s: { method: string; path: string }) => `${s.method} ${s.path}`;
export class AdaptiveLearner {
  private readonly pending: Observation[] = [];
  private readonly candidates: Observation[] = [];
  private readonly history: LearningModel[] = [];
  private model: LearningModel;
  private readonly sources: Set<string>;
  constructor(
    private readonly tenant: string,
    sources: string[],
    private readonly maxSamples = 10000,
    private readonly perSourceRoute = 20,
    private readonly minSources = 3,
  ) {
    if (
      sources.length < minSources ||
      sources.length > 1000 ||
      new Set(sources).size !== sources.length ||
      maxSamples < 1 ||
      perSourceRoute < 1 ||
      minSources < 2
    )
      throw new Error("Learning requires bounded, independently registered trusted sources");
    this.sources = new Set(sources);
    this.model = { version: 0, tenant, frozen: false, routes: [], createdAt: Date.now() };
  }
  observe(sample: Observation): { accepted: boolean; reason: string } {
    if (
      sample.tenant !== this.tenant ||
      !/^[A-Z]{1,20}$/.test(sample.method) ||
      sample.path.length > 1024 ||
      canonicalPath(sample.path) !== sample.path ||
      !Number.isFinite(sample.at) ||
      !Number.isSafeInteger(sample.bodyBytes) ||
      sample.bodyBytes < 0 ||
      sample.bodyBytes > 16777216 ||
      !Number.isInteger(sample.status) ||
      sample.status < 100 ||
      sample.status > 599 ||
      Object.keys(sample.fields).length > 128 ||
      Object.entries(sample.fields).some(
        ([k, v]) =>
          k.length > 128 || !["string", "number", "boolean", "object", "array", "null"].includes(v),
      )
    )
      throw new Error("Invalid learning observation");
    if (sample.trust !== "verified" || !this.sources.has(sample.source)) {
      if (this.candidates.length < this.maxSamples) this.candidates.push(structuredClone(sample));
      return { accepted: false, reason: "Candidate samples isolated from trusted baseline" };
    }
    if (this.model.frozen) return { accepted: false, reason: "Model frozen" };
    if (this.score(sample).score >= 50)
      return {
        accepted: false,
        reason: "Anomalous interval: learning paused for this observation",
      };
    if (this.pending.length >= this.maxSamples)
      return { accepted: false, reason: "Sample capacity reached" };
    if (
      this.pending.filter((s) => s.source === sample.source && routeKey(s) === routeKey(sample))
        .length >= this.perSourceRoute
    )
      return { accepted: false, reason: "Per-source route training quota reached" };
    this.pending.push(structuredClone(sample));
    return { accepted: true, reason: "Trusted sample staged for offline training" };
  }
  train(now = Date.now()): LearningModel {
    if (this.model.frozen) throw new Error("Frozen model cannot train");
    const grouped = new Map<string, Observation[]>();
    for (const s of this.pending) {
      const key = routeKey(s);
      const group = grouped.get(key) ?? [];
      group.push(s);
      grouped.set(key, group);
    }
    const routes = new Map(this.model.routes.map((r) => [routeKey(r), structuredClone(r)]));
    for (const [key, samples] of grouped) {
      const sourceCount = new Set(samples.map((s) => s.source)).size;
      if (sourceCount < this.minSources || (!routes.has(key) && routes.size >= 1000)) continue;
      const first = samples[0]!;
      const baseline: RouteBaseline = routes.get(key) ?? {
        path: first.path,
        method: first.method,
        samples: 0,
        sources: 0,
        meanBytes: 0,
        variance: 0,
        errorRate: 0,
        fields: Object.create(null),
      };
      // Equal source contribution: round-robin, truncated to the smallest source sample count.
      const bySource = [...new Set(samples.map((s) => s.source))]
        .sort()
        .map((source) => samples.filter((s) => s.source === source));
      const count = Math.min(...bySource.map((s) => s.length));
      for (let i = 0; i < count; i++)
        for (const group of bySource) {
          const s = group[i]!;
          const alpha = baseline.samples ? 0.1 : 1;
          const delta = s.bodyBytes - baseline.meanBytes;
          baseline.meanBytes += alpha * delta;
          baseline.variance = (1 - alpha) * (baseline.variance + alpha * delta * delta);
          baseline.errorRate += alpha * ((s.status >= 400 ? 1 : 0) - baseline.errorRate);
          baseline.samples = Math.min(baseline.samples + 1, 1_000_000_000);
          for (const [name, type] of Object.entries(s.fields)) {
            if (["__proto__", "constructor", "prototype"].includes(name)) continue;
            if (!Object.hasOwn(baseline.fields, name) && Object.keys(baseline.fields).length >= 128)
              continue;
            const types = baseline.fields[name] ?? [];
            if (!types.includes(type)) types.push(type);
            Object.defineProperty(baseline.fields, name, {
              value: types,
              writable: true,
              enumerable: true,
              configurable: true,
            });
          }
        }
      baseline.sources = sourceCount;
      routes.set(key, baseline);
    }
    this.history.push(structuredClone(this.model));
    if (this.history.length > 20) this.history.shift();
    this.model = {
      version: this.model.version + 1,
      tenant: this.tenant,
      routes: [...routes.values()],
      createdAt: now,
      frozen: false,
    };
    this.pending.length = 0;
    return this.snapshot();
  }
  score(sample: Observation): Anomaly {
    const baseline = this.model.routes.find((r) => routeKey(r) === routeKey(sample));
    const reasons: string[] = [];
    let score = 0;
    if (!baseline) {
      if (this.model.version > 0) {
        score += 25;
        reasons.push("Undeclared/new route relative to learned model");
      }
    } else {
      const bound = baseline.meanBytes + Math.max(1024, 4 * Math.sqrt(baseline.variance));
      if (sample.bodyBytes > bound) {
        score += 50;
        reasons.push(`Body size ${sample.bodyBytes} exceeds EWMA envelope ${Math.round(bound)}`);
      }
      for (const [key, type] of Object.entries(sample.fields)) {
        if (!Object.hasOwn(baseline.fields, key)) {
          score += 10;
          reasons.push(`New parameter: ${key}`);
        } else if (!baseline.fields[key]?.includes(type)) {
          score += 20;
          reasons.push(`Parameter type changed: ${key}`);
        }
      }
      if (sample.status >= 500 && baseline.errorRate < 0.1) {
        score += 20;
        reasons.push("Unexpected server failure");
      }
    }
    return { score: Math.min(score, 100), reasons, modelVersion: this.model.version };
  }
  freeze(): void {
    this.model.frozen = true;
    this.pending.length = 0;
  }
  rollback(version: number): LearningModel {
    const previous = this.history.find((m) => m.version === version);
    if (!previous) throw new Error("Model version unavailable");
    this.model = { ...structuredClone(previous), frozen: true };
    this.pending.length = 0;
    return this.snapshot();
  }
  snapshot(): LearningModel {
    return structuredClone(this.model);
  }
  get stagedCount(): number {
    return this.pending.length;
  }
  get candidateCount(): number {
    return this.candidates.length;
  }
}
