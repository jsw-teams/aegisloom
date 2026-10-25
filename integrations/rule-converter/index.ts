import { digest } from "../../packages/core/types.js";
import { loadPolicy, type Policy } from "../../packages/rule-ir/index.js";
export type ConversionStatus = "exact" | "runtime-only" | "partial" | "unsupported";
export interface ConversionReport {
  protocol: "shield-convert/1";
  source: {
    url: string;
    version: string;
    license: string;
    sha256: string;
    format: "seclang" | "crowdsec-appsec" | "suricata" | "sigma" | "nuclei";
  };
  status: ConversionStatus;
  limitations: string[];
  policy?: Policy;
}
export interface SourceIndexEntry {
  url: string;
  version: string;
  license: string;
  enabled: boolean;
}
/** No source downloads, scripts, third-party rules or format parsers live in Shield Core. */
export async function importConversion(
  report: ConversionReport,
  original: Uint8Array,
  permittedLicenses: string[],
): Promise<Policy> {
  if (
    report.protocol !== "shield-convert/1" ||
    !["exact", "runtime-only"].includes(report.status) ||
    !report.policy ||
    report.limitations.length > 0
  )
    throw new Error("Lossy/unsupported/unverified conversion cannot be activated");
  if (
    !report.source.version ||
    !permittedLicenses.includes(report.source.license) ||
    report.source.sha256 !== (await digest(original))
  )
    throw new Error("Unpinned source, checksum mismatch or unapproved license");
  const policy = loadPolicy(report.policy);
  for (const rule of policy.rules) {
    if (
      !rule.provenance ||
      rule.provenance.sha256 !== report.source.sha256 ||
      rule.provenance.license !== report.source.license ||
      rule.provenance.version !== report.source.version ||
      rule.provenance.source !== report.source.url ||
      rule.provenance.limitations.length
    )
      throw new Error("Missing or inconsistent rule provenance");
  }
  return policy;
}
