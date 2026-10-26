import { dirname, resolve } from "node:path";
import type { ConversionReport } from "../../integrations/rule-converter/index.js";
import { importSource } from "../../integrations/rule-converter/sources.js";
import { readData } from "../cli/config.js";
import { downloadSource, readSources } from "../cli/sources.js";
import { digest } from "../core/types.js";
import { verifySourcePolicy } from "./source-regression.js";
import type { SourceCandidate, SourceSyncStore } from "./source-sync-store.js";

export { applySources, buildSourcePolicy } from "./source-apply.js";
export { verifySourcePolicy } from "./source-regression.js";
export { SourceSyncStore } from "./source-sync-store.js";

/** Explicit background job. Does not publish rules, call origins, run external scripts or upload data. */
export async function synchronizeSources(
  file: string,
  store: SourceSyncStore,
  options: { now?: number; intervalMs?: number; transport?: typeof fetch } = {},
) {
  const config = await readSources(file),
    now = options.now ?? Date.now(),
    interval = options.intervalMs ?? 3600000;
  if (!Number.isSafeInteger(interval) || interval < 60000 || interval > 86400000)
    throw new Error("Sync interval must be 60..86400 seconds");
  const results: { source: string; result: string; hash?: string }[] = [];
  for (const source of config.ruleSources.filter((s) => s.enabled)) {
    if (!store.due(source.id, now, interval)) {
      results.push({ source: source.id, result: "not-due" });
      continue;
    }
    try {
      const bytes = await downloadSource(file, source, options.transport);
      const candidate: SourceCandidate = {
        source: source.id,
        hash: await digest(bytes),
        status: "needs-conversion",
        version: source.version,
        license: source.license,
        tests: 0,
      };
      if (source.format === "shield-ir" || source.conversionReportFile) {
        const report = source.conversionReportFile
          ? ((await readData(
              resolve(dirname(file), source.conversionReportFile),
            )) as ConversionReport)
          : undefined;
        candidate.policy = await importSource(config, source.id, bytes, report);
        candidate.status = "needs-regression";
        if (source.regressionFile) {
          candidate.tests = await verifySourcePolicy(
            candidate.policy,
            await readData(resolve(dirname(file), source.regressionFile)),
          );
          candidate.status = "verified";
        }
      }
      store.record(source.id, now, candidate.status, candidate, bytes);
      results.push({ source: source.id, result: candidate.status, hash: candidate.hash });
    } catch {
      // Never expose URL, transport error, response body or bearer credentials in diagnostics.
      store.record(source.id, now, "failed");
      results.push({ source: source.id, result: "failed" });
    }
  }
  return results;
}
