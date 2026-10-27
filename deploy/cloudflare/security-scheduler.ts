import { digest } from "../../packages/core/types.js";
import { importInventory } from "../../integrations/sbom/index.js";
import { verifySourcePolicy } from "../../packages/control-plane/source-regression.js";
import { loadPolicy } from "../../packages/rule-ir/index.js";
import { evaluateComponent, queryOsv } from "../../packages/vulnerability/osv.js";
import { proposeMitigation } from "../../packages/vulnerability/workflow.js";

interface KvStore {
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
}
export interface ScheduledSecurityEnvironment {
  SERVICE: string;
  SECURITY_KV?: KvStore;
  RULE_SOURCE_URL?: string;
  RULE_REGRESSIONS?: string;
  CVE_INVENTORY?: string;
  CVE_EMERGENCY_PATHS?: string;
}

export async function refreshSecurityCandidates(
  env: ScheduledSecurityEnvironment,
  transport: typeof fetch = fetch,
  now = Date.now(),
) {
  if (!env.RULE_SOURCE_URL && !env.CVE_INVENTORY)
    return { rules: "not-configured", cve: "not-configured" };
  if (!env.SECURITY_KV) throw new Error("SECURITY_KV required for scheduled scanning");
  let rules = "not-configured";
  let cve = "not-configured";
  if (env.RULE_SOURCE_URL) {
    if (!env.RULE_REGRESSIONS) throw new Error("RULE_REGRESSIONS required");
    const url = new URL(env.RULE_SOURCE_URL);
    if (url.protocol !== "https:" || url.username || url.password || url.hash)
      throw new Error("Approved HTTPS rule URL required");
    const response = await transport(url, {
      headers: { "accept-encoding": "identity" },
      redirect: "manual",
      signal: AbortSignal.timeout(10000),
    });
    const encoding = response.headers.get("content-encoding");
    if (response.status !== 200 || (encoding !== null && encoding !== "identity"))
      throw new Error("Invalid rule-source response");
    if (!response.body) throw new Error("Empty rule-source stream");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > 131072) throw new Error("Rule source exceeds 128 KiB");
        chunks.push(chunk.value);
      }
    } catch (error) {
      void reader.cancel().catch(() => {});
      throw error;
    }
    if (!size) throw new Error("Empty rule source");
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    const policy = loadPolicy(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!policy.rules.length || policy.rules.some((r) => r.service !== env.SERVICE))
      throw new Error("Rule scope mismatch or empty source");
    const tests = await verifySourcePolicy(policy, JSON.parse(env.RULE_REGRESSIONS), {
      requireRuleCoverage: true,
    });
    await env.SECURITY_KV.put("candidates/rules/latest", JSON.stringify({
      state: "verified-awaiting-approval", source: url.href,
      sha256: await digest(bytes), checkedAt: now, tests, policy, deployed: false,
    }), { expirationTtl: 604800 });
    rules = "verified-awaiting-approval";
  }
  if (env.CVE_INVENTORY) {
    const inventory = importInventory(JSON.parse(env.CVE_INVENTORY));
    if (inventory.length > 25) throw new Error("CVE inventory exceeds 25 components");
    const approved = env.CVE_EMERGENCY_PATHS
      ? JSON.parse(env.CVE_EMERGENCY_PATHS) as Record<string, string[]>
      : {};
    const findings: unknown[] = [];
    for (const component of inventory) {
      for (const advisory of await queryOsv(component, transport)) {
        const exposure = evaluateComponent(advisory, component);
        if (exposure.status === "not-affected") continue;
        const paths = approved[component.ecosystem + ":" + component.name] ?? [];
        if (!Array.isArray(paths) || paths.length > 20 ||
            paths.some((p) => typeof p !== "string" || !/^\/[A-Za-z0-9_./~-]*$/.test(p) || p.includes("..")))
          throw new Error("Invalid approved emergency paths");
        const candidate = proposeMitigation(
          advisory, component, env.SERVICE, paths,
          paths.length ? "feature-isolation" : "upgrade-required", now,
        );
        findings.push({ component, advisory: advisory.id, exposure,
          candidate, state: "review-required-not-deployed" });
        if (findings.length > 100) throw new Error("Too many CVE findings");
      }
    }
    await env.SECURITY_KV.put("candidates/cve/latest", JSON.stringify({
      checkedAt: now, findings, deployed: false,
    }), { expirationTtl: 604800 });
    cve = "review-required:" + findings.length;
  }
  return { rules, cve };
}
