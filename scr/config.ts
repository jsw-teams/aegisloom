import { parseDocument } from "yaml";
import type { BoundaryLimits } from "./http-boundary/index.js";
import type { PlatformName } from "./origin/types.js";
import type { Route } from "./runtime/index.js";
export interface DeploymentConfig {
  platform: PlatformName;
  tenant: string;
  service: string;
  publicHosts: string[];
  routes: Route[];
  secLangFile: string;
  localRulesFile?: string;
  allowlistFile?: string;
  secretFile: string;
  originDirectory: string;
  origins: Record<string, { origin: string; allowedOrigins: string[] }>;
  listen: { host: "127.0.0.1" | "::1" | "0.0.0.0" | "::"; port: number };
  allowLoopbackHttp?: boolean;
  limits?: Partial<BoundaryLimits>;
  maxConcurrentRequests?: number;
  responses?: { directory: string; contentSecurityPolicy: string };
}
export interface ProjectCredentials {
  originToken: string;
  clientToken?: string;
  ingressKey?: string;
}
export function parseConfigText(text: string): unknown {
  if (new TextEncoder().encode(text).length > 8_000_000)
    throw new Error("Configuration exceeds 8MB");
  const doc = parseDocument(text, { uniqueKeys: true, merge: false });
  if (doc.errors.length) throw new Error(doc.errors.map((e) => e.message).join("; "));
  return doc.toJS({ maxAliasCount: 0 });
}
export function validateDeploymentConfig(value: unknown): DeploymentConfig {
  const config = value as DeploymentConfig;
  const keys = [
    "tenant",
    "platform",
    "service",
    "publicHosts",
    "routes",
    "secLangFile",
    "localRulesFile",
    "allowlistFile",
    "secretFile",
    "originDirectory",
    "origins",
    "listen",
    "allowLoopbackHttp",
    "limits",
    "maxConcurrentRequests",
    "responses",
  ];
  if (
    !config ||
    typeof config !== "object" ||
    Object.keys(config).some((k) => !keys.includes(k)) ||
    !["cloudflare", "vercel", "netlify", "esa", "edgeone"].includes(config.platform) ||
    !Array.isArray(config.routes) ||
    !Array.isArray(config.publicHosts) ||
    config.publicHosts.length < 1 ||
    config.publicHosts.length > 16 ||
    !["tenant", "service", "secLangFile", "secretFile", "originDirectory"].every(
      (k) => typeof (config as any)[k] === "string" && (config as any)[k].length,
    ) ||
    !config.origins ||
    typeof config.origins !== "object" ||
    Array.isArray(config.origins) ||
    !["127.0.0.1", "::1", "0.0.0.0", "::"].includes(config.listen?.host) ||
    !Number.isInteger(config.listen.port) ||
    config.listen.port < 0 ||
    config.listen.port > 65535
  )
    throw new Error("Invalid deployment configuration");
  for (const route of config.routes) {
    if (
      !route ||
      typeof route.business !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(route.business) ||
      !Object.hasOwn(config.origins, route.business)
    )
      throw new Error("Every route must select a configured business");
  }
  for (const host of config.publicHosts) {
    const publicUrl = new URL(`https://${host}`);
    if (
      publicUrl.host !== host ||
      publicUrl.pathname !== "/" ||
      publicUrl.username ||
      publicUrl.password ||
      publicUrl.search ||
      publicUrl.hash
    )
      throw new Error("An exact public host is required");
  }
  if (
    config.responses &&
    (typeof config.responses.directory !== "string" ||
      !config.responses.directory ||
      typeof config.responses.contentSecurityPolicy !== "string" ||
      !config.responses.contentSecurityPolicy ||
      Object.keys(config.responses).some(
        (k) => !["directory", "contentSecurityPolicy"].includes(k),
      ))
  )
    throw new Error("Invalid custom response configuration");
  return config;
}
export function validateCredentials(value: unknown): ProjectCredentials {
  const credentials = value as ProjectCredentials;
  if (
    !credentials ||
    typeof credentials !== "object" ||
    Object.keys(credentials).some(
      (k) => !["originToken", "clientToken", "ingressKey"].includes(k),
    ) ||
    typeof credentials.originToken !== "string" ||
    !/^[\x21-\x7e]{32,2048}$/.test(credentials.originToken) ||
    (credentials.clientToken !== undefined &&
      (!/^[\x21-\x7e]{32,2048}$/.test(credentials.clientToken) ||
        credentials.clientToken === credentials.originToken))
  )
    throw new Error("Invalid project credentials");
  if (credentials.ingressKey !== undefined && !/^[\w-]{43,256}$/.test(credentials.ingressKey))
    throw new Error("Invalid ingress signing key");
  return credentials;
}
