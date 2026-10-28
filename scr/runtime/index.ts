import {
  digest,
  requireInteger,
  type SecurityEvent,
  ShieldError,
  stableJson,
  type TrustedContext,
} from "../core/types.js";
import {
  type BoundaryLimits,
  canonicalPath,
  checkBoundary,
  limitsWith,
  readBody,
} from "../http-boundary/index.js";
import { parseStrictJson } from "../http-boundary/json.js";
import { type CompileSecLangOptions, compileSecLang, executeSecLang } from "../seclang/index.js";
import { type AllowlistEntry, createAllowlist } from "./allowlist.js";
import { createErrorPages, type ErrorPages } from "./error-pages.js";
import { createProxy, type ProxyOptions } from "./proxy.js";

export type { SecurityEvent, TrustedContext } from "../core/types.js";
export type { AllowlistEntry } from "./allowlist.js";
export type { ProxyOptions } from "./proxy.js";

export interface Route {
  path: string;
  business: string;
  methods: string[];
  authenticated: boolean;
  body?: "json" | "text" | "none";
  /** Inspect the HTTP handshake; upgraded frames remain opaque to SecLang. */
  websocket?: boolean;
}
export interface ShieldOptions {
  tenant: string;
  service: string;
  publicHosts: string[];
  routes: Route[];
  /** Native SecLang rules, compiled and evaluated by EdgeShield itself (no conversion). */
  secLang: string;
  secLangOptions?: Omit<CompileSecLangOptions, "strict">;
  /** Fully operator-defined rule exemptions, including optional global bypass. */
  allowlist?: AllowlistEntry[];
  origins: Record<string, ProxyOptions>;
  limits?: Partial<BoundaryLimits>;
  maxConcurrentRequests?: number;
  event?: (event: SecurityEvent) => void;
  /** Optional trusted static pages; JSON API responses remain the default. */
  errorPages?: ErrorPages;
  now?: () => number;
}

export async function createShield(input: ShieldOptions) {
  // Capture immutable policy and config; callers cannot mutate enforcement after validation.
  const options = {
    ...input,
    routes: structuredClone(input.routes),
    publicHosts: [...input.publicHosts],
    allowlist: structuredClone(input.allowlist ?? []),
  };
  if (
    !/^[A-Za-z0-9_-]{1,64}$/.test(options.tenant) ||
    !/^[A-Za-z0-9_-]{1,64}$/.test(options.service)
  )
    throw new Error("Invalid tenant/service");
  if (typeof input.secLang !== "string" || !input.secLang.trim())
    throw new Error("Native secLang input is required");
  const version = await digest(
    stableJson({
      source: input.secLang,
      files: input.secLangOptions?.files ?? {},
      phraseFiles: input.secLangOptions?.phraseFiles ?? {},
      fileName: input.secLangOptions?.fileName ?? "main.conf",
      allowlist: options.allowlist,
    }),
  );
  const proxies = new Map<string, ReturnType<typeof createProxy>>();
  for (const [name, origin] of Object.entries(options.origins)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name)) throw new Error("Invalid business name");
    proxies.set(name, createProxy(origin));
  }
  if (!proxies.size) throw new Error("At least one business origin is required");
  const errorPages = createErrorPages(options.errorPages ?? {});
  const limits = limitsWith(options.limits);
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
    blocked: 0,
    originRequests: 0,
    eventFailures: 0,
  };
  const routes = new Map<string, Route>();
  for (const route of options.routes) {
    if (
      typeof route.authenticated !== "boolean" ||
      !proxies.has(route.business) ||
      (route.websocket !== undefined && typeof route.websocket !== "boolean") ||
      !Array.isArray(route.methods) ||
      ![undefined, "none", "json", "text"].includes(route.body)
    )
      throw new Error(
        "Routes require a configured business, explicit authenticated boolean, methods and a supported body profile",
      );
    if (
      canonicalPath(route.path) !== route.path ||
      routes.has(route.path) ||
      !route.methods.length ||
      route.methods.some((m) => !/^[A-Z]{1,20}$/.test(m) || ["CONNECT", "TRACE"].includes(m))
    )
      throw new Error("Invalid/duplicate route");
    routes.set(route.path, route);
  }
  let active = 0;
  const isAllowlisted = createAllowlist(options.allowlist);
  const nativeProgram = input.secLang
    ? compileSecLang(input.secLang, {
        ...input.secLangOptions,
        requestBodyLimit: limits.maxBodyBytes,
        now,
        strict: true,
      })
    : undefined;
  if (nativeProgram && !nativeProgram.supportedRules) {
    nativeProgram.dispose();
    throw new Error("SecLang ruleset is empty or unsupported");
  }
  let disposed = false;

  async function handle(
    request: Request,
    context: TrustedContext,
    rawTarget?: string,
    hooks: { event?: (event: SecurityEvent) => void } = {},
  ): Promise<Response> {
    const emit = (
      kind: SecurityEvent["kind"],
      source: SecurityEvent["source"],
      reason: string,
      ruleId?: string,
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
      for (const listener of [options.event, hooks.event])
        try {
          listener?.(event);
        } catch {
          stats.eventFailures++;
        }
    };
    const denied = (
      request: Request,
      status: number,
      source: SecurityEvent["source"],
      reason: string,
      ruleId?: string,
    ) => {
      stats.blocked++;
      emit("block", source, reason, ruleId);
      return (
        errorPages(request, status) ??
        Response.json(
          { error: "request_rejected", reason },
          { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } },
        )
      );
    };
    context = structuredClone(context);
    stats.requests++;
    if (disposed) return denied(request, 503, "boundary", "engine-closed");
    if (active >= maxConcurrent) return denied(request, 503, "boundary", "concurrency-capacity");
    active++;
    let released = false;
    const release = () => {
      if (!released) {
        active--;
        if (disposed && active === 0) nativeProgram?.dispose();
        released = true;
      }
    };
    let streaming = false;
    let pendingUpgrade: Response | undefined;
    let source: SecurityEvent["source"] = "boundary";
    try {
      if (context.tenant !== options.tenant) throw new ShieldError("tenant-mismatch", 403);
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
      const upgrade = request.headers.has("upgrade");
      const { url, path } = checkBoundary(
        request,
        limits,
        options.publicHosts,
        rawTarget,
        upgrade ? "websocket" : "http",
      );
      source = "route";
      const route = routes.get(path);
      if (!route) throw new ShieldError("unknown-route", 404);
      if (!route.methods.includes(request.method)) throw new ShieldError("method-not-allowed", 405);
      if (upgrade && !route.websocket) throw new ShieldError("websocket-route-required", 426);
      source = "identity";
      if (route.authenticated && !context.identity)
        throw new ShieldError("authentication-required", 401);
      source = "boundary";
      const body = await readBody(request, limits);
      const contentType = (request.headers.get("content-type") ?? "")
        .split(";")[0]!
        .trim()
        .toLowerCase();
      if (contentType === "application/grpc" || contentType.startsWith("application/grpc+"))
        throw new ShieldError("native-grpc-requires-http2-ingress", 501);
      if ((route.body ?? "none") === "none" && body.length)
        throw new ShieldError("body-not-allowed");
      let bodyText = "";
      if (body.length && route.body === "json") {
        try {
          bodyText = new TextDecoder("utf-8", { fatal: true }).decode(body);
        } catch {
          throw new ShieldError("invalid-utf8-body");
        }
      }
      if (body.length && route.body === "json") {
        if (
          !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
            request.headers.get("content-type") ?? "",
          )
        )
          throw new ShieldError("json-content-type-required", 415);
        parseStrictJson(bodyText);
      }
      const nativeInput = {
        url: url.href,
        method: request.method,
        headers: request.headers,
        bodyText,
        bodyBytes: body,
        protocol: context.httpProtocol,
        remoteAddr: context.verifiedClientIp,
        rawTarget,
      };
      const skipNativeRule = (id: string) =>
        isAllowlisted(path, request.method, context, id, now()) ||
        isAllowlisted(path, request.method, context, `sec-${id}`, now());
      let nativeTransaction: import("../seclang/index.js").SecLangTransaction | undefined;
      if (nativeProgram) {
        // Native SecLang runs AFTER route/auth/body limits and BEFORE origin forwarding.
        // Rejections are final; unsupported directives have already failed at configuration load.
        const native = executeSecLang(nativeProgram, nativeInput, {
          shouldSkip: skipNativeRule,
        });
        stats.ruleEvaluations += nativeProgram.supportedRules;
        nativeTransaction = native.transaction;
        if (native.blocked) {
          executeSecLang(
            nativeProgram,
            { ...nativeInput, responseStatus: native.status },
            {
              phases: [5],
              transaction: nativeTransaction,
              shouldSkip: skipNativeRule,
            },
          );
          return denied(
            request,
            native.status,
            "rule",
            "seclang-native-rule-match",
            native.matched.at(-1) ? `sec-${native.matched.at(-1)}` : undefined,
          );
        }
        if (native.transaction.bodyParseError) {
          executeSecLang(
            nativeProgram,
            { ...nativeInput, responseStatus: 400 },
            { phases: [5], transaction: native.transaction, shouldSkip: skipNativeRule },
          );
          return denied(request, 400, "boundary", "invalid-request-body");
        }
        for (const event of native.events)
          if (event.log) emit("detect", "rule", "seclang-native-observed", `sec-${event.id}`);
      }
      source = "proxy";
      stats.originRequests++;
      const inspectResponse = nativeProgram?.instructions.some(
        (rule) => "actions" in rule && Number(rule.actions.phase) >= 3,
      );
      let response = await proxies.get(route.business)!(
        request,
        url,
        path,
        body,
        inspectResponse ? () => {} : release,
        upgrade,
      );
      if (response.status === 101) pendingUpgrade = response;
      if (nativeProgram && inspectResponse && nativeTransaction) {
        const responseInput = {
          ...nativeInput,
          responseStatus: response.status,
          responseHeaders: response.headers,
        };
        const headersResult = executeSecLang(nativeProgram, responseInput, {
          phases: [3],
          transaction: nativeTransaction,
          shouldSkip: skipNativeRule,
        });
        if (headersResult.blocked) {
          closeUpgrade(response);
          await response.body?.cancel();
          executeSecLang(nativeProgram, responseInput, {
            phases: [5],
            transaction: nativeTransaction,
            shouldSkip: skipNativeRule,
          });
          return denied(
            request,
            headersResult.status,
            "rule",
            "seclang-response-rule-match",
            `sec-${headersResult.matched.at(-1)}`,
          );
        }
        const inspectBody = nativeProgram.instructions.some(
          (rule) => "actions" in rule && rule.actions.phase === 4,
        );
        if (response.status === 101) {
          const result = executeSecLang(
            nativeProgram,
            { ...responseInput, responseBodyBytes: new Uint8Array() },
            {
              phases: [4, 5],
              transaction: nativeTransaction,
              shouldSkip: skipNativeRule,
            },
          );
          if (result.blocked) {
            closeUpgrade(response);
            return denied(
              request,
              result.status,
              "rule",
              "seclang-response-rule-match",
              `sec-${result.matched.at(-1)}`,
            );
          }
          emit("allow", "proxy", "websocket-handshake-forwarded");
          pendingUpgrade = undefined;
          return response;
        }
        const bytes =
          inspectBody && response.body ? new Uint8Array(await response.arrayBuffer()) : undefined;
        const bodyResult = executeSecLang(
          nativeProgram,
          { ...responseInput, ...(bytes ? { responseBodyBytes: bytes } : {}) },
          {
            phases: inspectBody ? [4, 5] : [5],
            transaction: nativeTransaction,
            shouldSkip: skipNativeRule,
          },
        );
        if (bodyResult.blocked) {
          if (!bytes) await response.body?.cancel();
          return denied(
            request,
            bodyResult.status,
            "rule",
            "seclang-response-rule-match",
            `sec-${bodyResult.matched.at(-1)}`,
          );
        }
        if (bytes) {
          let sent = false;
          const stream = new ReadableStream<Uint8Array>(
            {
              pull(controller) {
                if (!sent && bytes.length) {
                  sent = true;
                  controller.enqueue(bytes);
                } else {
                  release();
                  controller.close();
                }
              },
              cancel() {
                release();
              },
            },
            { highWaterMark: 0 },
          );
          response = new Response(stream, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
          });
        } else if (response.body) {
          const reader = response.body.getReader();
          response = new Response(
            new ReadableStream<Uint8Array>(
              {
                async pull(controller) {
                  try {
                    const item = await reader.read();
                    if (item.done) {
                      release();
                      controller.close();
                    } else controller.enqueue(item.value);
                  } catch (error) {
                    release();
                    controller.error(error);
                  }
                },
                async cancel(reason) {
                  try {
                    await reader.cancel(reason);
                  } finally {
                    release();
                  }
                },
              },
              { highWaterMark: 0 },
            ),
            { status: response.status, statusText: response.statusText, headers: response.headers },
          );
        }
      }
      streaming = response.body !== null;
      emit("allow", "proxy", "forwarded");
      pendingUpgrade = undefined;
      return response;
    } catch (error) {
      if (error instanceof ShieldError) return denied(request, error.status, source, error.code);
      emit("error", source, "internal-error");
      return denied(request, 500, source, "internal-error");
    } finally {
      if (pendingUpgrade) closeUpgrade(pendingUpgrade);
      if (!streaming) release();
    }
  }
  return {
    handle: (
      request: Request,
      context: TrustedContext,
      rawTarget?: string,
      hooks?: { event?: (event: SecurityEvent) => void },
    ) => handle(request, context, rawTarget, hooks),
    version,
    dispose() {
      disposed = true;
      if (active === 0) nativeProgram?.dispose();
    },
    stats,
  };
}

function closeUpgrade(response: Response) {
  const socket = (
    response as Response & { webSocket?: { close(code: number, reason: string): void } }
  ).webSocket;
  try {
    socket?.close(1008, "Handshake rejected");
  } catch {
    /* Already closed. */
  }
}
