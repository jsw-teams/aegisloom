import { compileExpression, type MatchInput } from "../core/matcher.js";
import { RateWindows } from "../core/rate.js";
import {
  digest,
  requireInteger,
  type SecurityEvent,
  ShieldError,
  stableJson,
  type TrustedContext,
} from "../core/types.js";
import { type DecisionStore, LruTtl, type SecurityDecision } from "../decision-cache/index.js";
import {
  type BoundaryLimits,
  canonicalPath,
  checkBoundary,
  limitsWith,
  readBody,
} from "../http-boundary/index.js";
import { parseStrictJson } from "../http-boundary/json.js";
import {
  type GrpcWebProfile,
  grpcWebInspector,
  validateGrpcWebProfile,
} from "../protocols/grpc.js";
import { type MediaProfile, validateMediaProfile } from "../protocols/stream.js";
import { duration, loadPolicy, type Policy, policyVersion, visit } from "../rule-ir/index.js";
import { createProxy, type ProxyOptions } from "./proxy.js";

export type { SecurityEvent, TrustedContext } from "../core/types.js";
export type { ProxyOptions } from "./proxy.js";

export interface Route {
  path: string;
  methods: string[];
  authenticated: boolean;
  body?: "json" | "text" | "none" | "grpc-web";
  /** Opt-in media profile; keeps header rules, identity checks and decision caches. */
  media?: MediaProfile;
  protocol?: "http" | "websocket";
  grpcWeb?: GrpcWebProfile;
}
export interface ShieldOptions {
  tenant: string;
  service: string;
  publicHosts: string[];
  routes: Route[];
  policy: Policy;
  proxy: ProxyOptions;
  decisions: DecisionStore;
  limits?: Partial<BoundaryLimits>;
  cacheCapacity?: number;
  rateCapacity?: number;
  maxConcurrentRequests?: number;
  /** Explicit consistency/performance trade-off; 0 checks the epoch on every request. */
  revocationPollMs?: number;
  storageTimeoutMs?: number;
  storageFailure?: "closed" | "evaluate-rules";
  event?: (event: SecurityEvent) => void;
  /** Optional explicitly configured subscription; the subscriber enforces three independent consents. */
  community?: { shouldBlock(ip: string, now: number): boolean };
  now?: () => number;
}

export async function createShield(input: ShieldOptions) {
  // Capture immutable policy and config; callers cannot mutate enforcement after validation.
  const options = {
    ...input,
    routes: structuredClone(input.routes),
    publicHosts: [...input.publicHosts],
  };
  if (
    !/^[A-Za-z0-9_-]{1,64}$/.test(options.tenant) ||
    !/^[A-Za-z0-9_-]{1,64}$/.test(options.service)
  )
    throw new Error("Invalid tenant/service");
  const policy = loadPolicy(input.policy);
  const version = await policyVersion(policy);
  const rules = policy.rules
    .filter((r) => r.enabled && r.service === options.service)
    .map((rule) => {
      if (
        rule.phase === "response-headers" ||
        rule.then.action === "challenge" ||
        rule.placement === "upstream-required" ||
        rule.placement === "edge-required"
      )
        throw new Error(
          `Unsupported runtime semantics for ${rule.id}; explicit L0/upstream enforcement required`,
        );
      return { rule, match: compileExpression(rule.when) };
    });
  const proxy = createProxy(options.proxy);
  // Trace IDs vary on otherwise identical attacks. Keep them whenever any active rule observes them.
  const observedHeaders = new Set<string>();
  for (const { rule } of rules)
    visit(rule.when, (m) => {
      if (m.field === "header") observedHeaders.add(m.key!.toLowerCase());
    });
  const traceHeaders = new Set(["cf-ray", "x-vercel-id", "x-nf-request-id"]);
  const limits = limitsWith(options.limits);
  const l1 = new LruTtl<SecurityDecision>(options.cacheCapacity);
  const negativeL2 = new LruTtl<boolean>(options.cacheCapacity);
  const windows = new RateWindows(options.rateCapacity);
  const pollMs = requireInteger(options.revocationPollMs ?? 1000, 0, 60000, "revocation poll");
  const storageTimeout = requireInteger(
    options.storageTimeoutMs ?? 1000,
    1,
    30000,
    "storage timeout",
  );
  const maxConcurrent = requireInteger(
    options.maxConcurrentRequests ?? 64,
    1,
    10000,
    "max concurrent requests",
  );
  const now = options.now ?? Date.now;
  const stats = {
    requests: 0,
    ruleEvaluations: 0,
    l1Hits: 0,
    l2Hits: 0,
    blocked: 0,
    originRequests: 0,
    eventFailures: 0,
    storageFailures: 0,
  };
  const routes = new Map<string, Route>();
  for (const route of options.routes) {
    if (
      typeof route.authenticated !== "boolean" ||
      !Array.isArray(route.methods) ||
      ![undefined, "none", "json", "text", "grpc-web"].includes(route.body)
    )
      throw new Error(
        "Routes require explicit authenticated boolean, methods and a supported body profile",
      );
    if (
      canonicalPath(route.path) !== route.path ||
      routes.has(route.path) ||
      !route.methods.length ||
      route.methods.some((m) => !/^[A-Z]{1,20}$/.test(m) || ["CONNECT", "TRACE"].includes(m))
    )
      throw new Error("Invalid/duplicate route");
    if (![undefined, "http", "websocket"].includes(route.protocol))
      throw new Error("Unknown route protocol");
    if (
      route.protocol === "websocket" &&
      (route.media ||
        route.methods.some((m) => m !== "GET") ||
        ![undefined, "none"].includes(route.body))
    )
      throw new Error("WebSocket routes require GET without body/media");
    if (route.media) {
      route.media = validateMediaProfile(route.media);
      if (
        route.methods.some((m) => !["GET", "HEAD"].includes(m)) ||
        ![undefined, "none"].includes(route.body)
      )
        throw new Error("Media routes require GET/HEAD without a request body");
    }
    if (route.grpcWeb || route.body === "grpc-web") {
      if (
        !route.grpcWeb ||
        route.body !== "grpc-web" ||
        route.media ||
        route.protocol === "websocket" ||
        route.methods.some((m) => m !== "POST")
      )
        throw new Error(
          "gRPC-Web requires POST, its binary body profile and no media/WebSocket mode",
        );
      route.grpcWeb = validateGrpcWebProfile(route.grpcWeb);
      for (const { rule } of rules) {
        if (rule.phase === "request-body")
          throw new Error("Text/JSON body rules are incompatible with gRPC-Web binary semantics");
        visit(rule.when, (m) => {
          if (m.field === "body")
            throw new Error("Body rules require schema-aware gRPC-Web support");
        });
      }
    }
    routes.set(route.path, route);
  }
  let generation = -1;
  let nextPoll = 0;
  let active = 0;
  async function storage<T>(operation: () => Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        operation(),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error("storage-timeout")), storageTimeout);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
  const emit = (
    kind: SecurityEvent["kind"],
    source: SecurityEvent["source"],
    reason: string,
    ruleId?: string,
    decisionId?: string,
  ) => {
    const event: SecurityEvent = {
      id: crypto.randomUUID(),
      tenant: options.tenant,
      at: now(),
      kind,
      source,
      reason,
      policy: version,
    };
    if (ruleId) event.ruleId = ruleId;
    if (decisionId) event.decisionId = decisionId;
    try {
      options.event?.(event);
    } catch {
      stats.eventFailures++;
    }
  };
  const denied = (
    status: number,
    source: SecurityEvent["source"],
    reason: string,
    ruleId?: string,
    decisionId?: string,
  ) => {
    stats.blocked++;
    emit("block", source, reason, ruleId, decisionId);
    return Response.json(
      { error: "request_rejected", reason },
      { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } },
    );
  };
  async function handle(
    request: Request,
    context: TrustedContext,
    rawTarget?: string,
    mode: "http" | "websocket" = "http",
  ): Promise<Response> {
    context = structuredClone(context);
    stats.requests++;
    if (active >= maxConcurrent) return denied(503, "boundary", "concurrency-capacity");
    active++;
    let released = false;
    const release = () => {
      if (!released) {
        active--;
        released = true;
      }
    };
    let streaming = false;
    let source: SecurityEvent["source"] = "boundary";
    try {
      if (context.tenant !== options.tenant) throw new ShieldError("tenant-mismatch", 403);
      if (
        context.riskScore !== undefined &&
        (!Number.isFinite(context.riskScore) || context.riskScore < 0 || context.riskScore > 100)
      )
        throw new ShieldError("invalid-trusted-score", 403);
      if (
        context.identity !== undefined &&
        (context.identity.length === 0 || context.identity.length > 256)
      )
        throw new ShieldError("invalid-trusted-identity", 403);
      if (
        context.verifiedClientIp !== undefined &&
        (context.verifiedClientIp.length > 64 || !/^[0-9a-fA-F:.]+$/.test(context.verifiedClientIp))
      )
        throw new ShieldError("invalid-verified-ip", 403);
      const { url, path } = checkBoundary(request, limits, options.publicHosts, rawTarget, mode);
      source = "route";
      const route = routes.get(path);
      if (!route) throw new ShieldError("unknown-route", 404);
      if ((route.protocol ?? "http") !== mode)
        throw new ShieldError("route-protocol-mismatch", 426);
      if (!route.methods.includes(request.method)) throw new ShieldError("method-not-allowed", 405);
      source = "identity";
      if (route.authenticated && !context.identity)
        throw new ShieldError("authentication-required", 401);
      if (
        context.verifiedClientIp &&
        options.community?.shouldBlock(context.verifiedClientIp, now())
      )
        return denied(403, "community", "opted-in-community-decision");
      source = "boundary";
      const body = await readBody(request, limits);
      const contentType = (request.headers.get("content-type") ?? "")
        .split(";")[0]!
        .trim()
        .toLowerCase();
      if (contentType === "application/grpc" || contentType.startsWith("application/grpc+"))
        throw new ShieldError("native-grpc-requires-http2-ingress", 501);
      if (route.grpcWeb) {
        if (
          !["application/grpc-web", "application/grpc-web+proto"].includes(contentType) ||
          (request.headers.has("grpc-encoding") &&
            request.headers.get("grpc-encoding") !== "identity")
        )
          throw new ShieldError("unsupported-grpc-web-encoding", 415);
        try {
          grpcWebInspector({ ...route.grpcWeb, direction: "request" })(body, true);
        } catch {
          throw new ShieldError("invalid-grpc-web-frame", 400);
        }
      }
      if ((route.body ?? "none") === "none" && body.length)
        throw new ShieldError("body-not-allowed");
      const requiresBody = rules.some(({ rule }) => rule.phase === "request-body");
      let bodyText = "";
      if (body.length && (requiresBody || route.body === "json" || route.body === "text")) {
        try {
          bodyText = new TextDecoder("utf-8", { fatal: true }).decode(body);
        } catch {
          throw new ShieldError("invalid-utf8-body");
        }
      }
      let json: unknown;
      if (body.length && route.body === "json") {
        if (
          !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
            request.headers.get("content-type") ?? "",
          )
        )
          throw new ShieldError("json-content-type-required", 415);
        json = parseStrictJson(bodyText);
      }
      for (const { rule } of rules)
        visit(rule.when, (m) => {
          if (m.field === "body" && m.key && body.length && route.body !== "json")
            throw new ShieldError("json-pointer-on-non-json-route", 415);
        });
      const matchInput: MatchInput = { request, url, path, bodyText, context, json };
      const key = await digest(
        stableJson([
          options.tenant,
          options.service,
          mode,
          version,
          request.method,
          url.href,
          [...request.headers].filter(
            ([name]) => !traceHeaders.has(name) || observedHeaders.has(name),
          ),
          await digest(body),
          context,
        ]),
      );
      const timestamp = now();
      let storageAvailable = true;
      source = "storage";
      try {
        if (generation < 0 || timestamp >= nextPoll) {
          const current = await storage(() => options.decisions.generation(options.tenant));
          if (!Number.isSafeInteger(current) || current < generation)
            throw new Error("Non-monotonic generation");
          if (current !== generation) {
            l1.clear();
            negativeL2.clear();
            generation = current;
          }
          nextPoll = timestamp + pollMs;
        }
      } catch {
        stats.storageFailures++;
        l1.clear();
        generation = -1;
        storageAvailable = false;
        if (options.storageFailure === "closed")
          throw new ShieldError("decision-store-unavailable", 503);
      }
      const local = storageAvailable ? l1.get(key, timestamp) : undefined;
      if (local && local.generation === generation && local.policy === version && !local.revoked) {
        stats.l1Hits++;
        return denied(403, "l1", "cached-attack", local.ruleId, local.id);
      }
      if (storageAvailable && !negativeL2.get(key, timestamp)) {
        try {
          const remote = await storage(() => options.decisions.get(options.tenant, key, timestamp));
          if (!remote) negativeL2.set(key, true, timestamp + 1000);
          if (
            remote &&
            remote.tenant === options.tenant &&
            remote.key === key &&
            remote.generation === generation &&
            remote.policy === version &&
            !remote.revoked &&
            remote.expiresAt > timestamp
          ) {
            l1.set(key, remote, remote.expiresAt);
            stats.l2Hits++;
            return denied(403, "l2", "distributed-attack", remote.ruleId, remote.id);
          }
        } catch {
          stats.storageFailures++;
          if (options.storageFailure === "closed")
            throw new ShieldError("decision-store-unavailable", 503);
          storageAvailable = false;
        }
      }
      source = "rule";
      for (const { rule, match } of rules) {
        if (rule.expiresAt && Date.parse(rule.expiresAt) <= timestamp) continue;
        stats.ruleEvaluations++;
        if (!match(matchInput)) continue;
        if (rule.requests) {
          const group =
            rule.requests.groupBy === "identity" ? context.identity : context.verifiedClientIp;
          if (!group) throw new ShieldError("verified-rate-identity-required", 403);
          if (
            !windows.hit(
              stableJson([options.tenant, version, rule.id, group]),
              rule.requests.moreThan,
              duration(rule.requests.within),
              rule.then.action === "rate-limit" ? duration(rule.then.duration!) : 0,
              timestamp,
            )
          )
            continue;
        }
        if (rule.then.action === "detect") {
          context.riskScore = Math.min(100, (context.riskScore ?? 0) + (rule.then.score ?? 0));
          emit("detect", "rule", "rule-match", rule.id);
          continue;
        }
        let decisionId: string | undefined;
        if (rule.cache.enabled && storageAvailable) {
          const expiresAt = Math.min(
            timestamp + duration(rule.cache.ttl),
            rule.expiresAt ? Date.parse(rule.expiresAt) : Number.MAX_SAFE_INTEGER,
          );
          const decision: SecurityDecision = {
            id: crypto.randomUUID(),
            tenant: options.tenant,
            key,
            policy: version,
            ruleId: rule.id,
            source: "rule",
            confidence: 0.5,
            evidenceHash: key,
            firstSeen: timestamp,
            lastSeen: timestamp,
            expiresAt,
            generation,
            version: 1,
            revoked: false,
            cloud: "unsupported",
          };
          try {
            if (await storage(() => options.decisions.put(decision, generation))) {
              l1.set(key, decision, expiresAt);
              decisionId = decision.id;
            }
          } catch {
            stats.storageFailures++; /* A failed cache write never prevents the rule's block. */
          }
        }
        return denied(
          rule.then.action === "rate-limit" ? 429 : 403,
          "rule",
          "rule-match",
          rule.id,
          decisionId,
        );
      }
      source = "proxy";
      if (mode === "websocket") {
        emit("allow", "proxy", "websocket-handshake-approved");
        return new Response(null, { status: 204 });
      }
      stats.originRequests++;
      const response = await proxy(request, url, path, body, release, route.media, route.grpcWeb);
      streaming = response.body !== null;
      emit("allow", "proxy", "forwarded");
      return response;
    } catch (error) {
      if (error instanceof ShieldError) return denied(error.status, source, error.code);
      emit("error", source, "internal-error");
      return denied(500, source, "internal-error");
    } finally {
      if (!streaming) release();
    }
  }
  return {
    handle: (request: Request, context: TrustedContext, rawTarget?: string) =>
      handle(request, context, rawTarget),
    inspectWebSocket: (request: Request, context: TrustedContext) =>
      handle(request, context, undefined, "websocket"),
    version,
    stats,
    cache: l1,
  };
}
