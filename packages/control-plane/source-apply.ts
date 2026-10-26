import { open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { readData } from "../cli/config.js";
import { importConfiguredSource, readSources } from "../cli/sources.js";
import { loadPolicy, policyVersion } from "../rule-ir/index.js";
import { validateHeaderPolicy } from "../runtime/header-policy.js";
import { verifySourcePolicy } from "./source-regression.js";

/** Complete rebuild from current authorized sources; a failed source keeps the active file intact. */
export async function buildSourcePolicy(file: string, transport: typeof fetch = fetch) {
  const config = await readSources(file),
    application = config.application;
  if (!application) throw new Error("No automatic application authorization configured");
  const path = (name: string) => resolve(dirname(file), name);
  const baseline = validateHeaderPolicy(
    loadPolicy(await readData(path(application.baselineFile))),
    application.service,
  );
  const rules = [...baseline.rules];
  const sources: { id: string; tests: number }[] = [];
  for (const source of config.ruleSources.filter((source) => source.enabled && source.autoApply)) {
    if (!source.regressionFile || source.service !== application.service)
      throw new Error(
        "Every applied source requires regression samples and the application service",
      );
    const report = source.conversionReportFile
      ? ((await readData(
          path(source.conversionReportFile),
        )) as import("../../integrations/rule-converter/index.js").ConversionReport)
      : undefined;
    const policy = validateHeaderPolicy(
      await importConfiguredSource(file, source.id, report, transport),
      application.service,
    );
    const tests = await verifySourcePolicy(policy, await readData(path(source.regressionFile)), {
      requireRuleCoverage: true,
    });
    rules.push(...policy.rules);
    sources.push({ id: source.id, tests });
  }
  // Removing/disablement of a source removes its rules on the next successful rebuild.
  const policy = loadPolicy({ version: "1", rules });
  const tests = await verifySourcePolicy(policy, await readData(path(application.regressionFile)), {
    requireRuleCoverage: true,
  });
  return {
    policy,
    sources,
    tests,
    version: await policyVersion(policy),
    target: path(application.policyFile),
  };
}

export async function applySources(file: string, transport: typeof fetch = fetch) {
  const config = await readSources(file);
  if (!config.application) throw new Error("No automatic application authorization configured");
  const target = resolve(dirname(file), config.application.policyFile),
    lock = `${target}.apply-lock`;
  const samePath = (left: string, right: string) =>
    process.platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right;
  const inputs = [
    file,
    ...[
      config.application.baselineFile,
      config.application.regressionFile,
      ...config.ruleSources.flatMap((source) => [
        ...(!source.location.startsWith("https://") ? [source.location] : []),
        ...(source.regressionFile ? [source.regressionFile] : []),
        ...(source.conversionReportFile ? [source.conversionReportFile] : []),
      ]),
    ].map((name) => resolve(dirname(file), name)),
  ];
  if (inputs.some((input) => samePath(resolve(input), target)))
    throw new Error("Application output must not overwrite configuration or source inputs");
  const lease = await open(lock, "wx", 0o600);
  const temporary = `${target}.${crypto.randomUUID()}.tmp`;
  try {
    const built = await buildSourcePolicy(file, transport);
    const bytes = `${JSON.stringify(built.policy, null, 2)}\n`;
    if (Buffer.byteLength(bytes) > 131072) throw new Error("Applied policy exceeds 128KiB");
    const previous = await readFile(target, "utf8").catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
      return undefined;
    });
    if (previous === bytes)
      return { applied: false, version: built.version, tests: built.tests, sources: built.sources };
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, target);
    return { applied: true, version: built.version, tests: built.tests, sources: built.sources };
  } finally {
    await unlink(temporary).catch(() => {});
    await lease.close();
    await unlink(lock);
  }
}
