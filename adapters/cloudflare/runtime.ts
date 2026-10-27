import { digest, type Fetch, type TrustedContext } from "../../packages/core/types.js";
import { HttpDecisionStore } from "../../packages/decision-cache/http.js";
import { loadPolicy } from "../../packages/rule-ir/index.js";
import { type AllowlistEntry, createShield, type Route } from "../../packages/runtime/index.js";
import { createCloudflareWebSocketGateway } from "./websocket.js";

interface FetchBinding {
  fetch(request: Request): Promise<Response>;
}
export interface WorkerEnvironment {
  TENANT: string;
  SERVICE: string;
  PUBLIC_HOST: string;
  ORIGIN: string;
  ORIGIN_TOKEN: string;
  CONTROL_ORIGIN: string;
  CONTROL_RUNTIME_TOKEN: string;
  POLICY: string;
  /** Optional operator-managed JSON whitelist; deployment owner decides all scopes. */
  ALLOWLIST?: string;
  ROUTES: Route[];
  /** Optional service-to-service bearer identity; not a replacement for an application's sessions. */
  CLIENT_TOKEN?: string;
  WEBSOCKET_BROWSER_ORIGINS?: string[];
  ORIGIN_SERVICE?: FetchBinding;
  CONTROL_SERVICE?: FetchBinding;
}
const bindingFetch = (binding?: FetchBinding): Fetch =>
  binding ? (input, init) => binding.fetch(new Request(input, init)) : fetch;

/** Caller may inject actual application authentication; defaults support one machine bearer identity. */
export async function createCloudflareRuntime(
  env: WorkerEnvironment,
  authenticate?: (request: Request) => Promise<Omit<TrustedContext, "tenant" | "verifiedClientIp">>,
) {
  if (env.CLIENT_TOKEN !== undefined && !/^[\x21-\x7e]{32,2048}$/.test(env.CLIENT_TOKEN))
    throw new Error("Invalid client credential");
  const clientHash = env.CLIENT_TOKEN ? await digest(env.CLIENT_TOKEN) : undefined;
  const context = async (request: Request): Promise<Omit<TrustedContext, "tenant">> => {
    const ip = request.headers.get("cf-connecting-ip");
    const verified: Omit<TrustedContext, "tenant"> = authenticate
      ? await authenticate(request)
      : {};
    // Only this real Cloudflare entry trusts its platform-provided IP header.
    if (ip) verified.verifiedClientIp = ip;
    if (!authenticate && clientHash) {
      const auth = request.headers.get("authorization") ?? "";
      if (
        auth.length <= 2055 &&
        auth.startsWith("Bearer ") &&
        (await digest(auth.slice(7))) === clientHash
      )
        verified.identity = "configured-service-client";
    }
    return verified;
  };
  const engine = await createShield({
    tenant: env.TENANT,
    service: env.SERVICE,
    publicHosts: [env.PUBLIC_HOST],
    routes: env.ROUTES,
    policy: loadPolicy(env.POLICY),
    ...(env.ALLOWLIST ? { allowlist: JSON.parse(env.ALLOWLIST) as AllowlistEntry[] } : {}),
    decisions: new HttpDecisionStore(
      env.CONTROL_ORIGIN,
      env.CONTROL_RUNTIME_TOKEN,
      env.TENANT,
      bindingFetch(env.CONTROL_SERVICE),
    ),
    proxy: {
      origin: env.ORIGIN,
      allowedOrigins: [env.ORIGIN],
      originToken: env.ORIGIN_TOKEN,
      fetch: bindingFetch(env.ORIGIN_SERVICE),
    },
  });
  const websocket = env.ROUTES.some((r) => r.protocol === "websocket")
    ? createCloudflareWebSocketGateway({
        tenant: env.TENANT,
        engine,
        origin: env.ORIGIN,
        allowedOrigins: [env.ORIGIN],
        originToken: env.ORIGIN_TOKEN,
        allowedBrowserOrigins: env.WEBSOCKET_BROWSER_ORIGINS ?? [],
        context,
        fetch: bindingFetch(env.ORIGIN_SERVICE),
      })
    : undefined;
  return async (request: Request) => {
    if (request.headers.get("upgrade")?.toLowerCase() === "websocket")
      return websocket
        ? websocket(request)
        : Response.json(
            { error: "websocket_not_configured" },
            { status: 426, headers: { "cache-control": "no-store" } },
          );
    return engine.handle(request, { ...(await context(request)), tenant: env.TENANT });
  };
}
