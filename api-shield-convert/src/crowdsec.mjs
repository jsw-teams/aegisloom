import { parseDocument } from "yaml";

export function parseCrowdSec(source) {
  const doc = parseDocument(source, { uniqueKeys: true, merge: false });
  if (doc.errors.length) throw new Error("Invalid CrowdSec YAML");
  const raw = doc.toJS({ maxAliasCount: 0 });
  if (!raw || typeof raw !== "object" || Object.keys(raw).some((k) => !["name", "description", "rules", "labels"].includes(k)) || !Array.isArray(raw.rules) || raw.rules.length !== 1) return { rules: [], limitations: ["CrowdSec configuration/hooks/multiple-rule semantics unsupported"] };
  const leaf = raw.rules[0];
  if (!leaf || Object.keys(leaf).some((k) => !["zones", "match", "transform"].includes(k)) || JSON.stringify(leaf.zones) !== '["METHOD"]' || (leaf.transform?.length ?? 0) !== 0 || Object.keys(leaf.match ?? {}).some((k) => !["type", "value"].includes(k)) || leaf.match?.type !== "equals" || !/^[A-Z]{1,20}$/.test(leaf.match.value)) return { rules: [], limitations: ["Only untransformed METHOD equality is supported; decoders, selectors and regex semantics require native AppSec"] };
  // CrowdSec alert/scenario remediation is not equivalent to an inline block.
  return { rules: [{ id: "crowdsec-method", name: String(raw.name ?? "CrowdSec method detection"), phase: "request-headers", when: { field: "method", op: "eq", value: leaf.match.value }, then: { action: "detect" } }], limitations: ["Condition translated; CrowdSec in-band alerts, out-band events, scenarios and IP remediation are NOT reproduced. Explicit operator policy required."] };
}
