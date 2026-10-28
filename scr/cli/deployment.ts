import { realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { type DeploymentConfig, validateDeploymentConfig } from "../config.js";
import type { BusinessFunction, OriginSettings, PlatformName } from "../origin/types.js";
import { readData } from "./config.js";

export async function readDeployment(path: string, platform?: PlatformName) {
  const directory = dirname(resolve(path));
  const input = (await readData(path)) as Record<string, unknown>;
  platform ??= input.platform as PlatformName;
  if (!["cloudflare", "vercel", "netlify", "esa", "edgeone"].includes(platform))
    throw new Error("Select a cloud platform for the business origins");
  if (typeof input.originDirectory !== "string" || Object.hasOwn(input, "origins"))
    throw new Error(
      "Business origins must be configured in origin/<platform>/<business>/config.yml",
    );
  if (!Array.isArray(input.routes) || !input.routes.length)
    throw new Error("At least one business route is required");
  const names = [
    ...new Set(
      input.routes.map((route) => {
        if (
          !route ||
          typeof route.business !== "string" ||
          !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(route.business)
        )
          throw new Error("Every route must select a valid business name");
        return route.business as string;
      }),
    ),
  ];
  const originRoot = await realpath(resolve(directory, input.originDirectory));
  const platformRoot = await realpath(resolve(originRoot, platform));
  if (relative(originRoot, platformRoot) !== platform)
    throw new Error("Cross-platform origin path is forbidden");
  const businesses: Record<
    string,
    { settings: OriginSettings; originFile: string; businessFile: string }
  > = Object.create(null);
  const origins: DeploymentConfig["origins"] = Object.create(null);
  for (const name of names) {
    const businessRoot = await realpath(resolve(platformRoot, name));
    if (relative(platformRoot, businessRoot) !== name)
      throw new Error("Business directory must remain within its platform");
    const originFile = await realpath(resolve(businessRoot, "config.yml"));
    if (dirname(originFile) !== businessRoot)
      throw new Error("Origin config must remain in its business directory");
    const settings = (await readData(originFile, 65536)) as OriginSettings;
    if (
      !settings ||
      settings.platform !== platform ||
      !["function", "relay", "proxy"].includes(settings.mode)
    )
      throw new Error("Origin platform or mode mismatch");
    const keys =
      settings.mode === "proxy"
        ? ["platform", "mode", "url"]
        : settings.mode === "relay"
          ? ["platform", "mode", "endpoint", "publicKeyFile", "authenticationKeyFile"]
          : ["platform", "mode"];
    if (Object.keys(settings).some((key) => !keys.includes(key)))
      throw new Error("Unknown business origin option");
    let origin = `https://${name.toLowerCase()}.origin.internal`;
    let businessFile = resolve(businessRoot, "index.js");
    if (settings.mode === "function") {
      businessFile = await realpath(businessFile);
      if (dirname(businessFile) !== businessRoot)
        throw new Error("Business entry must remain in its business directory");
    }
    if (settings.mode === "proxy") {
      const url = new URL(settings.url);
      if (
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        url.pathname !== "/" ||
        url.search ||
        url.hash
      )
        throw new Error("Proxy origin must be an exact HTTPS origin (IP, hostname or CNAME)");
      origin = url.origin;
    }
    if (settings.mode === "relay") {
      const endpoint = new URL(settings.endpoint);
      if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.hash)
        throw new Error("Relay endpoint must use HTTPS without credentials or fragments");
      const secretRoot = await realpath(resolve(directory, "secret"));
      for (const field of ["publicKeyFile", "authenticationKeyFile"] as const) {
        if (typeof settings[field] !== "string") throw new Error("Relay key file is required");
        const file = await realpath(resolve(businessRoot, settings[field]));
        const rel = relative(secretRoot, file);
        if (rel.startsWith("..") || isAbsolute(rel))
          throw new Error("Relay keys must reside in the project secret directory");
        settings[field] = file;
      }
    }
    businesses[name] = { settings, originFile, businessFile };
    origins[name] = { origin, allowedOrigins: [origin] };
  }
  const config = validateDeploymentConfig({ ...input, platform, origins });
  config.secLangFile = resolve(directory, config.secLangFile);
  if (config.localRulesFile) config.localRulesFile = resolve(directory, config.localRulesFile);
  config.secretFile = resolve(directory, config.secretFile);
  if (config.allowlistFile) config.allowlistFile = resolve(directory, config.allowlistFile);
  if (config.responses) config.responses.directory = resolve(directory, config.responses.directory);
  return { config, businesses, originRoot, platformRoot };
}
export async function readBusinessFunction(path: string): Promise<BusinessFunction> {
  const module = await import(pathToFileURL(path).href);
  const business = module.default;
  if (!business || typeof business.fetch !== "function")
    throw new Error("Business origin must export a fetch function");
  return business;
}
export { readCredentials, readData } from "./config.js";
export { readResponsePages } from "./responses.js";
