#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import type { ConversionReport } from "../../integrations/rule-converter/index.js";
import { importInventory } from "../../integrations/sbom/index.js";
import { validateBackendPolicy } from "../backend-security/index.js";
import {
  createCloudflareAdapter,
  createEdgeOneAdapter,
  createEsaAdapter,
  createNetlifyAdapter,
  createVercelAdapter,
} from "../cloud-compiler/index.js";
import { SHIELD_VERSION } from "../core/version.js";
import { MemoryDecisionStore } from "../decision-cache/index.js";
import { AdaptiveLearner, anomalyCandidate, type Observation } from "../learning/index.js";
import { explain, loadPolicy, policyVersion } from "../rule-ir/index.js";
import { createShield } from "../runtime/index.js";
import { evaluateComponent, queryOsv, VulnerabilityDatabase } from "../vulnerability/index.js";
import { readData } from "./config.js";
import { importConfiguredSource, readSources } from "./sources.js";

const usage = `ShieldWeave
  shieldweave validate|explain <policy.yaml>
  shieldweave backend-check <backend-policy.yaml>
  shieldweave simulate <policy.yaml> <samples.json>
  shieldweave compatibility <policy.yaml> [maxRules=5]
  shieldweave serve <shield.yaml>
  shieldweave sources-check <sources.yaml>
  shieldweave sources-import <sources.yaml> <source-id> <output.json> [conversion-report.json]
  shieldweave sources-sync <sources.yaml> <candidates.db> [interval-seconds=3600]
  shieldweave sources-watch <sources.yaml> <candidates.db> [interval-seconds=3600]
  shieldweave sources-export <candidates.db> <source-id> <hash> <new-policy.json>
  shieldweave control <state.db> <tenant> [port=8790]
  shieldweave assess <inventory.json> <osv-records.json>
  shieldweave osv-query <inventory.json> <output.json>   (explicit outbound package metadata)
  shieldweave learn <observations.json> <model.json> <tenant> <source1,source2,source3>
  shieldweave revoke <state.db> <tenant> <decision-id>
  shieldweave --help
Cloud publication is available through the typed SDK with exact-plan approval; this CLI never auto-publishes.
`;
export async function main(args = process.argv.slice(2)): Promise<void> {
  const [command, file, second, third, fourth] = args;
  if (command === "--version" || command === "-v") {
    console.log(SHIELD_VERSION);
    return;
  }
  if (!command || command === "--help") {
    process.stdout.write(usage);
    return;
  }
  if (!file) throw new Error(usage);
  if (command === "sources-export") {
    if (!second || !third || !fourth)
      throw new Error("Source ID, candidate hash and new output file required");
    const { SourceSyncStore } = await import("../control-plane/source-sync-store.js");
    const store = new SourceSyncStore(file);
    try {
      const candidate = store.candidate(second, third);
      if (!candidate?.policy || candidate.status !== "verified")
        throw new Error("Only verified candidates may be exported for review");
      await writeFile(fourth, JSON.stringify(candidate.policy, null, 2), {
        flag: "wx",
        mode: 0o600,
      });
      console.log(JSON.stringify({ source: second, exported: true, activated: false }));
    } finally {
      store.close();
    }
    return;
  }
  if (command === "sources-check") {
    const config = await readSources(file);
    console.log(
      JSON.stringify({
        valid: true,
        upstreams: config.upstreams.length,
        ruleSources: config.ruleSources.length,
      }),
    );
    return;
  }
  if (command === "sources-sync" || command === "sources-watch") {
    if (!second) throw new Error("Candidate database path required");
    const interval = Number(third ?? 3600) * 1000;
    if (!Number.isSafeInteger(interval) || interval < 60000 || interval > 86400000)
      throw new Error("Sync interval must be 60..86400 seconds");
    const { SourceSyncStore, synchronizeSources } = await import("../control-plane/source-sync.js");
    const { setTimeout: delay } = await import("node:timers/promises");
    const store = new SourceSyncStore(second),
      abort = new AbortController();
    const stop = () => abort.abort();
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    try {
      do {
        const results = await synchronizeSources(file, store, { intervalMs: interval });
        console.log(JSON.stringify({ results, activated: false }));
        if (command !== "sources-watch") {
          if (results.some((r) => r.result === "failed")) process.exitCode = 1;
          break;
        }
        await delay(Math.min(interval, 60000), undefined, { signal: abort.signal }).catch(() => {});
      } while (!abort.signal.aborted);
    } finally {
      process.off("SIGINT", stop);
      process.off("SIGTERM", stop);
      store.close();
    }
    return;
  }
  if (command === "sources-import") {
    if (!second || !third) throw new Error("Source ID and new output file required");
    const report = fourth ? ((await readData(fourth)) as ConversionReport) : undefined;
    const policy = await importConfiguredSource(file, second, report);
    await writeFile(third, JSON.stringify(policy, null, 2), { flag: "wx" });
    console.log(
      JSON.stringify({
        imported: second,
        rules: policy.rules.length,
        output: third,
        deployment: "not-deployed; run regression tests and explicitly activate the policy",
      }),
    );
    return;
  }
  if (command === "backend-check") {
    const policy = validateBackendPolicy(await readData(file));
    console.log(
      JSON.stringify({
        valid: true,
        profile: "shield-backend-json-v1",
        service: policy.service,
        routes: policy.routes.length,
        verification: "configuration-only; application and ingress tests still required",
      }),
    );
    return;
  }
  if (command === "serve") {
    const { serve } = await import("./serve.js");
    await serve(file);
    return;
  }
  if (command === "control") {
    const { serveControl } = await import("./serve.js");
    if (!second) throw new Error("Tenant required");
    await serveControl(file, second, Number(third ?? 8790));
    return;
  }
  if (command === "revoke") {
    if (!second || !third) throw new Error("Tenant and decision ID required");
    const { SqliteAuthority } = await import("../control-plane/sqlite.js");
    const store = new SqliteAuthority(file);
    try {
      console.log(JSON.stringify({ generation: await store.revoke(second, third, Date.now()) }));
    } finally {
      store.close();
    }
    return;
  }
  if (command === "assess" || command === "osv-query") {
    if (!second) throw new Error("Output/advisory file required");
    const inventory = importInventory(await readData(file));
    if (command === "osv-query") {
      const db = new VulnerabilityDatabase();
      for (const component of inventory) db.ingest(await queryOsv(component));
      await writeFile(second, JSON.stringify(db.all(), null, 2));
      return;
    }
    const input = await readData(second);
    const db = new VulnerabilityDatabase();
    db.ingest(Array.isArray(input) ? input : [input]);
    console.log(
      JSON.stringify(
        inventory.flatMap((c) =>
          db.all().map((r) => ({ component: c, advisory: r.id, ...evaluateComponent(r, c) })),
        ),
        null,
        2,
      ),
    );
    return;
  }
  if (command === "learn") {
    if (!second || !third || !fourth)
      throw new Error("Output, tenant and independently registered sources required");
    const samples = (await readData(file)) as Observation[];
    if (!Array.isArray(samples) || samples.length > 10000)
      throw new Error("Invalid observation batch");
    const learner = new AdaptiveLearner(third, fourth.split(","));
    for (const sample of samples) learner.observe(sample);
    const model = learner.train();
    await writeFile(
      second,
      JSON.stringify(
        { model, candidates: model.routes.map((r) => anomalyCandidate("api", r.path, r.method)) },
        null,
        2,
      ),
    );
    return;
  }
  const policy = loadPolicy(await readFile(file, "utf8"));
  if (command === "validate") {
    console.log(
      JSON.stringify({
        valid: true,
        rules: policy.rules.length,
        hash: await policyVersion(policy),
      }),
    );
    return;
  }
  if (command === "explain") {
    for (const rule of policy.rules) console.log(explain(rule));
    return;
  }
  if (command === "compatibility") {
    const config = {
      tenant: "report",
      service: policy.rules[0]?.service ?? "api",
      maxRules: Number(second ?? 5),
    };
    for (const adapter of [
      createCloudflareAdapter(config),
      createEsaAdapter(config),
      createVercelAdapter(config),
      createEdgeOneAdapter(config),
      createNetlifyAdapter(config.tenant, config.service),
    ])
      console.log(
        JSON.stringify({
          capabilities: adapter.capabilities(),
          rules: policy.rules.map((r) => adapter.compile(r)),
        }),
      );
    return;
  }
  if (command === "simulate") {
    if (!second) throw new Error("Regression samples file required");
    const samples = (await readData(second)) as any[];
    if (!Array.isArray(samples) || samples.length > 10000) throw new Error("Invalid sample set");
    const paths = [...new Set(samples.map((s) => new URL(s.url).pathname))];
    const engine = await createShield({
      tenant: "simulation",
      service: policy.rules[0]?.service ?? "api",
      publicHosts: ["simulation.test"],
      routes: paths.map((path) => ({
        path,
        methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        authenticated: false,
        body: "json",
      })),
      policy,
      decisions: new MemoryDecisionStore(),
      proxy: {
        origin: "https://origin.invalid",
        allowedOrigins: ["https://origin.invalid"],
        originToken: "offline-simulation-origin-token-only",
        fetch: async () => new Response(null, { status: 204 }),
      },
    });
    let failures = 0;
    for (const sample of samples) {
      const url = new URL(sample.url);
      if (url.host !== "simulation.test")
        throw new Error("Simulation samples must use simulation.test; no network is sent");
      const response = await engine.handle(
        new Request(url, {
          method: sample.method ?? "GET",
          headers: sample.headers,
          ...(sample.body !== undefined ? { body: sample.body } : {}),
        }),
        {
          tenant: "simulation",
          verifiedClientIp: sample.ip ?? "192.0.2.1",
          ...(sample.identity ? { identity: sample.identity } : {}),
        },
      );
      const passed = response.status === sample.expectedStatus;
      if (!passed) failures++;
      console.log(
        JSON.stringify({
          name: sample.name,
          actual: response.status,
          expected: sample.expectedStatus,
          passed,
        }),
      );
      await response.body?.cancel();
    }
    if (failures) throw new Error(`${failures} regression samples failed`);
    return;
  }
  throw new Error(`Unknown command ${command}`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href)
  main().catch((error: Error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
