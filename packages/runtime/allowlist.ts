import ipaddr from "ipaddr.js";
import type { TrustedContext } from "../core/types.js";

export interface AllowlistEntry {
  /** Operator-defined identifier for auditing. */
  id: string;
  /** Bypass any rule, or only the listed rule IDs. "*" means every rule. */
  ruleIds?: string[];
  /** Scope to either individual WAF rules or optional community intelligence. */
  skip: ("rules" | "community")[];
  /** All filters below are optional. Omitting them matches all requests. */
  path?: string;
  pathPrefix?: string;
  methods?: string[];
  identity?: string;
  verifiedClientIp?: string;
  cidrs?: string[];
  /** Optional ISO-8601 expiration: no forced lifetime. */
  expiresAt?: string;
  reason?: string;
}

interface Prepared {
  entry: AllowlistEntry;
  cidrs: [ipaddr.IPv4 | ipaddr.IPv6, number][];
  expiry: number;
}
/** All bypass scope and expiry are operator-managed. No automatic whitelist entries. */
export function createAllowlist(entries: AllowlistEntry[] = []) {
  if (!Array.isArray(entries)) throw new Error("Allowlist must be an array");
  const prepared: Prepared[] = entries.map((entry) => {
    if (!entry || typeof entry.id !== "string" || !entry.id.trim())
      throw new Error("Allowlist entry requires an id");
    if (
      !Array.isArray(entry.skip) ||
      !entry.skip.length ||
      entry.skip.some((value) => value !== "rules" && value !== "community")
    )
      throw new Error("Allowlist skip must select rules and/or community");
    if (
      entry.ruleIds !== undefined &&
      (!Array.isArray(entry.ruleIds) || entry.ruleIds.some((x) => typeof x !== "string" || !x))
    )
      throw new Error("Allowlist ruleIds must be an array of rule names or *");
    if (
      entry.methods !== undefined &&
      (!Array.isArray(entry.methods) ||
        entry.methods.some((x) => typeof x !== "string" || !/^[A-Z]+$/.test(x)))
    )
      throw new Error("Allowlist methods must be uppercase HTTP methods");
    if (entry.path !== undefined && (typeof entry.path !== "string" || !entry.path.startsWith("/")))
      throw new Error("Allowlist path must be an absolute request path");
    if (
      entry.pathPrefix !== undefined &&
      (typeof entry.pathPrefix !== "string" || !entry.pathPrefix.startsWith("/"))
    )
      throw new Error("Allowlist pathPrefix must be an absolute request path prefix");
    if (entry.identity !== undefined && (typeof entry.identity !== "string" || !entry.identity))
      throw new Error("Allowlist identity must be a nonempty string");
    if (entry.verifiedClientIp !== undefined && !ipaddr.isValid(entry.verifiedClientIp))
      throw new Error("Allowlist exact IP is invalid");
    if (
      entry.cidrs !== undefined &&
      (!Array.isArray(entry.cidrs) || entry.cidrs.some((x) => typeof x !== "string"))
    )
      throw new Error("Allowlist CIDRs must be strings");
    const cidrs = (entry.cidrs ?? []).map((value) => {
      try {
        return ipaddr.parseCIDR(value);
      } catch {
        throw new Error("Invalid allowlist CIDR");
      }
    });
    const expiry =
      entry.expiresAt === undefined ? Number.POSITIVE_INFINITY : Date.parse(entry.expiresAt);
    if (Number.isNaN(expiry)) throw new Error("Invalid allowlist expiration");
    if (entry.reason !== undefined && typeof entry.reason !== "string")
      throw new Error("Invalid allowlist reason");
    return { entry, cidrs, expiry };
  });
  return (
    path: string,
    method: string,
    context: TrustedContext,
    ruleId: string | null,
    scope: "rules" | "community",
    now: number,
  ) =>
    prepared.some(({ entry, cidrs, expiry }) => {
      if (!entry.skip.includes(scope) || now >= expiry) return false;
      if (
        scope === "rules" &&
        entry.ruleIds &&
        !entry.ruleIds.includes("*") &&
        (ruleId === null || !entry.ruleIds.includes(ruleId))
      )
        return false;
      if (entry.path !== undefined && entry.path !== path) return false;
      if (entry.pathPrefix !== undefined && !path.startsWith(entry.pathPrefix)) return false;
      if (entry.methods !== undefined && !entry.methods.includes(method)) return false;
      if (entry.identity !== undefined && entry.identity !== context.identity) return false;
      if (
        entry.verifiedClientIp !== undefined &&
        entry.verifiedClientIp !== context.verifiedClientIp
      )
        return false;
      if (entry.cidrs !== undefined) {
        if (!context.verifiedClientIp) return false;
        let actual: ipaddr.IPv4 | ipaddr.IPv6;
        try {
          actual = ipaddr.process(context.verifiedClientIp);
        } catch {
          return false;
        }
        if (
          !cidrs.some(([address, prefix]) => {
            const candidate = ipaddr.process(address.toString());
            return actual.kind() === candidate.kind() && actual.match(candidate, prefix);
          })
        )
          return false;
      }
      return true;
    });
}
