import { mkdir, writeFile } from "node:fs/promises";
import { arch, cpus, platform } from "node:os";
import { MemoryDecisionStore } from "../packages/decision-cache/index.js";
import { loadPolicy } from "../packages/rule-ir/index.js";
import { createShield } from "../packages/runtime/index.js";

const iterations = Number(process.env.SHIELD_BENCH_REQUESTS ?? 3000);
if (!Number.isInteger(iterations) || iterations < 100 || iterations > 100000)
  throw new Error("Benchmark request count must be 100..100000");
const store = new MemoryDecisionStore();
const policy = loadPolicy({
  version: "1",
  rules: [
    {
      id: "marker",
      name: "benchmark marker",
      service: "api",
      when: { field: "query", key: "q", op: "eq", value: "attack" },
      then: { action: "block" },
      cache: { enabled: true, ttl: "1h" },
    },
  ],
});
const config = {
  tenant: "bench",
  service: "api",
  publicHosts: ["bench.test"],
  routes: [{ path: "/api", methods: ["GET"], authenticated: false }],
  policy,
  decisions: store,
  proxy: {
    origin: "https://origin.invalid",
    allowedOrigins: ["https://origin.invalid"],
    originToken: "offline-benchmark-origin-token-only",
    fetch: async () => new Response(null, { status: 204 }),
  },
};
const engine = await createShield(config);
const second = await createShield(config);
const context = { tenant: "bench", verifiedClientIp: "192.0.2.1" };
const results: Record<string, unknown> = {};
const percentile = (sorted: number[], p: number) =>
  sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
for (const scenario of ["allow", "first-rule", "l1", "l2"] as const) {
  const target = scenario === "l2" ? second : engine;
  const initial = { ...target.stats };
  const latencies: number[] = [];
  const cpu = process.cpuUsage();
  const memory = process.memoryUsage().heapUsed;
  for (let i = 0; i < iterations; i++) {
    const path =
      scenario === "allow"
        ? "/api"
        : scenario === "first-rule"
          ? `/api?q=attack&unique=${i}`
          : "/api?q=attack";
    if (scenario === "l2") second.cache.clear();
    const start = performance.now();
    const response = await target.handle(new Request(`https://bench.test${path}`), context);
    latencies.push(performance.now() - start);
    await response.body?.cancel();
  }
  const used = process.cpuUsage(cpu);
  latencies.sort((a, b) => a - b);
  results[scenario] = {
    requests: iterations,
    p50Ms: percentile(latencies, 0.5),
    p95Ms: percentile(latencies, 0.95),
    p99Ms: percentile(latencies, 0.99),
    cpuMicrosecondsPerRequest: (used.user + used.system) / iterations,
    heapDeltaBytes: process.memoryUsage().heapUsed - memory,
    l1HitRate: (target.stats.l1Hits - initial.l1Hits) / iterations,
    l2HitRate: (target.stats.l2Hits - initial.l2Hits) / iterations,
    ruleEvaluationsPerRequest:
      (target.stats.ruleEvaluations - initial.ruleEvaluations) / iterations,
    attackOriginReachRate:
      scenario === "allow"
        ? null
        : (target.stats.originRequests - initial.originRequests) / iterations,
    syntheticNormalBlockRate:
      scenario === "allow" ? (target.stats.blocked - initial.blocked) / iterations : null,
  };
}
const decision = (await store.list("bench", Date.now())).at(-1);
const before = performance.now();
if (decision) await store.revoke("bench", decision.id, Date.now());
const revocationMs = performance.now() - before;
const report = {
  at: new Date().toISOString(),
  environment: { node: process.version, platform: platform(), arch: arch(), cpu: cpus()[0]?.model },
  kind: "offline-in-process-only",
  results,
  stats: engine.stats,
  l2Stats: second.stats,
  memory: process.memoryUsage(),
  revocationAuthorityTransactionMs: revocationMs,
  unavailable: [
    "Cloud POP enforcement latency",
    "Cross-region L2 latency",
    "Real traffic false-positive rate",
    "Streaming origin throughput",
    "Raw HTTP/2 HTTP/3 protocol performance",
  ],
};
await mkdir("artifacts", { recursive: true });
await writeFile("artifacts/benchmark.json", JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
