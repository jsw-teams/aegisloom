import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { parseDocument } from "yaml";
import type { Route } from "../runtime/index.js";

export interface RunConfig {
  tenant: string;
  service: string;
  publicHosts: string[];
  routes: Route[];
  policyFile: string;
  origin?: string;
  allowedOrigins?: string[];
  originTokenEnv?: string;
  upstream?: { file: string; id: string };
  clientTokenEnv?: string;
  listen: { host: "127.0.0.1" | "::1" | "0.0.0.0" | "::"; port: number };
  allowLoopbackHttp?: boolean;
  decisions: { kind: "sqlite"; path: string } | { kind: "http"; url: string; tokenEnv: string };
}
export async function readData(path: string): Promise<unknown> {
  const bytes = await readFile(path);
  if (bytes.length > 8_000_000) throw new Error("Input file exceeds 8MB");
  const doc = parseDocument(bytes.toString("utf8"), { uniqueKeys: true, merge: false });
  if (doc.errors.length) throw new Error(doc.errors.map((e) => e.message).join("; "));
  return doc.toJS({ maxAliasCount: 0 });
}
export function envSecret(name: string): string {
  if (!/^[A-Z][A-Z0-9_]{0,127}$/.test(name))
    throw new Error("Invalid secret environment variable name");
  const value = process.env[name];
  if (!value || !/^[\x21-\x7e]{32,2048}$/.test(value))
    throw new Error(`Set ${name} to a secret of at least 32 characters`);
  return value;
}
export async function readRunConfig(path: string): Promise<RunConfig> {
  const raw = (await readData(path)) as RunConfig;
  const allowed = [
    "tenant",
    "service",
    "publicHosts",
    "routes",
    "policyFile",
    "origin",
    "allowedOrigins",
    "originTokenEnv",
    "clientTokenEnv",
    "listen",
    "decisions",
    "upstream",
    "allowLoopbackHttp",
  ];
  if (
    !raw ||
    typeof raw !== "object" ||
    Object.keys(raw).some((key) => !allowed.includes(key)) ||
    !raw.tenant ||
    !raw.service ||
    !Array.isArray(raw.routes) ||
    !Array.isArray(raw.publicHosts) ||
    raw.publicHosts.length !== 1 ||
    typeof raw.publicHosts[0] !== "string" ||
    typeof raw.policyFile !== "string" ||
    (raw.upstream
      ? !raw.upstream.file ||
        !raw.upstream.id ||
        Object.keys(raw.upstream).some((k) => !["file", "id"].includes(k)) ||
        raw.origin !== undefined ||
        raw.originTokenEnv !== undefined ||
        raw.allowedOrigins !== undefined
      : !Array.isArray(raw.allowedOrigins) ||
        typeof raw.origin !== "string" ||
        typeof raw.originTokenEnv !== "string") ||
    !["127.0.0.1", "::1", "0.0.0.0", "::"].includes(raw.listen?.host) ||
    (raw.allowLoopbackHttp !== undefined && typeof raw.allowLoopbackHttp !== "boolean") ||
    !Number.isInteger(raw.listen.port) ||
    raw.listen.port < 0 ||
    raw.listen.port > 65535 ||
    !["sqlite", "http"].includes(raw.decisions?.kind)
  )
    throw new Error(
      "Invalid run configuration; explicitly select a listen IP and use a TLS ingress for external access",
    );
  const publicUrl = new URL(`https://${raw.publicHosts[0]}`);
  if (
    publicUrl.host !== raw.publicHosts[0] ||
    publicUrl.pathname !== "/" ||
    publicUrl.username ||
    publicUrl.password ||
    publicUrl.search ||
    publicUrl.hash
  )
    throw new Error(
      "CLI requires one exact canonical public Host; listener address is configured separately",
    );
  raw.policyFile = resolve(dirname(resolve(path)), raw.policyFile);
  if (raw.upstream) raw.upstream.file = resolve(dirname(resolve(path)), raw.upstream.file);
  if (raw.decisions.kind === "sqlite")
    raw.decisions.path = resolve(dirname(resolve(path)), raw.decisions.path);
  return raw;
}
