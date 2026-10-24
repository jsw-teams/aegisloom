import { requireInteger } from "../core/types.js";
import { canonicalPath } from "../http-boundary/index.js";

export interface BackendRoute {
  path: string;
  methods: string[];
  auth: "public" | "bearer" | "session";
  body: "none" | "json";
}
/** Executable JSON API profile, not a declaration that an existing backend is compliant. */
export interface BackendPolicy {
  version: "1";
  tenant: string;
  service: string;
  hosts: string[];
  /** Public browser origins; independent of an internal origin host after proxying. */
  sessionOrigins: string[];
  routes: BackendRoute[];
  maxBodyBytes: number;
  timeoutMs: number;
  maxConcurrentRequests: number;
}
function keys(value: unknown, allowed: string[]): asserts value is Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => !allowed.includes(key))
  )
    throw new Error("Invalid backend policy object or unknown property");
}
export function validateBackendPolicy(input: unknown): BackendPolicy {
  keys(input, [
    "version",
    "tenant",
    "service",
    "hosts",
    "sessionOrigins",
    "routes",
    "maxBodyBytes",
    "timeoutMs",
    "maxConcurrentRequests",
  ]);
  const p = structuredClone(input) as unknown as BackendPolicy;
  if (
    p.version !== "1" ||
    typeof p.tenant !== "string" ||
    typeof p.service !== "string" ||
    !/^[A-Za-z0-9_-]{1,64}$/.test(p.tenant) ||
    !/^[A-Za-z0-9_-]{1,64}$/.test(p.service) ||
    !Array.isArray(p.hosts) ||
    !p.hosts.length ||
    p.hosts.length > 16 ||
    p.hosts.some(
      (host) =>
        typeof host !== "string" ||
        !/^[a-z0-9.-]+(?::[0-9]{1,5})?$/.test(host) ||
        new URL(`https://${host}`).host !== host,
    ) ||
    !Array.isArray(p.routes) ||
    !p.routes.length ||
    p.routes.length > 1000
  )
    throw new Error("Invalid backend version, scope, hosts or routes");
  requireInteger(p.maxBodyBytes, 0, 1048576, "backend body limit");
  requireInteger(p.timeoutMs, 1, 30000, "backend timeout");
  requireInteger(p.maxConcurrentRequests, 1, 256, "backend concurrency");
  if (
    !Array.isArray(p.sessionOrigins) ||
    p.sessionOrigins.length > 16 ||
    p.sessionOrigins.some((value) => {
      if (typeof value !== "string") return true;
      try {
        const url = new URL(value);
        return url.protocol !== "https:" || url.origin !== value;
      } catch {
        return true;
      }
    })
  )
    throw new Error("Explicit HTTPS session origins required");
  const paths = new Set<string>();
  for (const route of p.routes) {
    keys(route, ["path", "methods", "auth", "body"]);
    if (
      typeof route.path !== "string" ||
      route.path.includes("?") ||
      canonicalPath(route.path) !== route.path ||
      paths.has(route.path) ||
      !Array.isArray(route.methods) ||
      !route.methods.length ||
      route.methods.length > 7 ||
      route.methods.some(
        (m) => !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(m),
      ) ||
      new Set(route.methods).size !== route.methods.length ||
      !["public", "bearer", "session"].includes(route.auth) ||
      !["none", "json"].includes(route.body)
    )
      throw new Error("Invalid or duplicate backend route");
    paths.add(route.path);
    if (
      route.auth === "session" &&
      route.methods.some((m) => !["GET", "HEAD", "OPTIONS"].includes(m)) &&
      !p.sessionOrigins.length
    )
      throw new Error("Session mutations require approved public browser origins");
  }
  return p;
}
