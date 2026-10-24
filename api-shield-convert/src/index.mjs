import { createHash } from "node:crypto";
import { parseSecLang } from "./seclang.mjs";
import { parseCrowdSec } from "./crowdsec.mjs";

export function convert(source, metadata) {
  if (typeof source !== "string" || Buffer.byteLength(source) > 131072 || !metadata || !metadata.url || !metadata.version || !metadata.license || !metadata.service) throw new Error("Bounded source and pinned origin/version/license/service required");
  const sha256 = createHash("sha256").update(source).digest("hex");
  if (metadata.sha256 && metadata.sha256 !== sha256) throw new Error("Source checksum mismatch");
  let parsed;
  if (metadata.format === "seclang") parsed = parseSecLang(source);
  else if (metadata.format === "crowdsec-appsec") parsed = parseCrowdSec(source);
  else parsed = { rules: [], limitations: [`${metadata.format} is not equivalent to an HTTP WAF; unsupported format`] };
  if (new Set(parsed.rules.map((r) => r.id)).size !== parsed.rules.length) parsed.limitations.push("Duplicate rule IDs");
  const status = parsed.limitations.length ? (parsed.rules.length ? "partial" : "unsupported") : parsed.rules.length ? "exact" : "unsupported";
  const origin = { url: metadata.url, version: metadata.version, license: metadata.license, format: metadata.format, sha256 };
  return { protocol: "shield-convert/1", source: origin, status, limitations: parsed.limitations, ...(parsed.rules.length ? { policy: { version: "1", rules: parsed.rules.map((r, i) => ({ ...r, service: metadata.service, enabled: true, priority: i + 100, placement: "runtime-required", cache: { enabled: false, ttl: "1m" }, community: { report: false }, provenance: { source: metadata.url, version: metadata.version, license: metadata.license, sha256, limitations: [...parsed.limitations] } })) } } : {}) };
}
