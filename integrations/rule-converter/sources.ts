import { Ajv } from "ajv";
import { digest } from "../../packages/core/types.js";
import { loadPolicy, type Policy } from "../../packages/rule-ir/index.js";
import { type ConversionReport, importConversion } from "./index.js";
import schema from "./sources.schema.json" with { type: "json" };

export interface UpstreamSource {
  id: string;
  kind: "cloud" | "vps" | "local";
  origin: string;
  originTokenEnv: string;
  timeoutMs: number;
  maxResponseBytes: number;
}
export interface RuleSource {
  id: string;
  enabled: boolean;
  location: string;
  format: "shield-ir" | ConversionReport["source"]["format"];
  version: string;
  license: string;
  service: string;
  authTokenEnv?: string;
  regressionFile?: string;
  conversionReportFile?: string;
  autoApply?: boolean;
}
export interface SourceConfig {
  version: "1";
  upstreams: UpstreamSource[];
  ruleSources: RuleSource[];
  permittedLicenses: string[];
  application?: {
    policyFile: string;
    baselineFile: string;
    regressionFile: string;
    service: string;
  };
}
// Control-plane configuration validation only; never imported by the online runtime.
const validate = new Ajv({ allErrors: true, strict: false }).compile(schema);
export function validateSources(input: unknown): SourceConfig {
  if (!validate(input))
    throw new Error(`Invalid source configuration: ${JSON.stringify(validate.errors)}`);
  const config = structuredClone(input) as unknown as SourceConfig;
  if (config.application) {
    const { policyFile, baselineFile, regressionFile } = config.application;
    for (const file of [policyFile, baselineFile, regressionFile])
      if (file.startsWith("/") || /^[a-z]:|^\\\\/i.test(file) || file.split(/[\\/]/).includes(".."))
        throw new Error("Application files must remain within the configuration directory");
    if (new Set([policyFile, baselineFile, regressionFile]).size !== 3)
      throw new Error("Application input and output files must be distinct");
  }
  for (const list of [config.upstreams, config.ruleSources])
    if (new Set(list.map((s) => s.id)).size !== list.length) throw new Error("Duplicate source ID");
  for (const upstream of config.upstreams) {
    const url = new URL(upstream.origin);
    if (url.protocol !== "https:" || url.username || url.password || url.origin !== upstream.origin)
      throw new Error("Upstream requires an exact HTTPS origin without credentials/path/query");
  }
  for (const source of config.ruleSources) {
    if (!config.permittedLicenses.includes(source.license))
      throw new Error("Unapproved source license");
    if (source.location.startsWith("https://")) {
      const url = new URL(source.location);
      if (
        url.username ||
        url.password ||
        url.hash ||
        /(?:token|secret|password|key)=/i.test(url.search)
      )
        throw new Error("Invalid rule source URL");
    } else if (/^[a-z][a-z0-9+.-]*:/i.test(source.location) || source.location.startsWith("\\\\"))
      throw new Error("Rule sources require HTTPS or an operator-owned relative file");
    else if (source.location.startsWith("/") || source.location.split(/[\\/]/).includes(".."))
      throw new Error("Local rule source must remain within its configuration directory");
    if (source.authTokenEnv && !source.location.startsWith("https://"))
      throw new Error("Source credentials require HTTPS");
    for (const file of [source.regressionFile, source.conversionReportFile])
      if (
        file &&
        (file.startsWith("/") || /^[a-z]:|^\\\\/i.test(file) || file.split(/[\\/]/).includes(".."))
      )
        throw new Error("Source auxiliary file must remain within its configuration directory");
  }
  return config;
}

/** Computes provenance from the received bytes; imports are candidates, never auto-activated. */
export async function importSource(
  config: SourceConfig,
  id: string,
  bytes: Uint8Array,
  report?: ConversionReport,
): Promise<Policy> {
  const checked = validateSources(config);
  const source = checked.ruleSources.find((s) => s.id === id && s.enabled);
  if (!source) throw new Error("Unknown or disabled rule source");
  if (bytes.length > 131072) throw new Error("Source size limit exceeded");
  const sha256 = await digest(bytes);
  let policy: Policy;
  if (source.format === "shield-ir") {
    if (report) throw new Error("Native IR source does not accept a converter report");
    policy = loadPolicy(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    // Record actual bytes and configured metadata, replacing self-asserted provenance.
    for (const rule of policy.rules)
      rule.provenance = {
        source: source.location,
        version: source.version,
        sha256,
        license: source.license,
        limitations: [],
      };
  } else {
    if (
      !report ||
      report.source.url !== source.location ||
      report.source.version !== source.version ||
      report.source.sha256 !== sha256 ||
      report.source.license !== source.license ||
      report.source.format !== source.format
    )
      throw new Error("Conversion does not match configured source");
    policy = await importConversion(report, bytes, checked.permittedLicenses);
  }
  if (!policy.rules.length || policy.rules.some((rule) => rule.service !== source.service))
    throw new Error("Imported policy has an empty or inconsistent service scope");
  return loadPolicy(policy);
}
