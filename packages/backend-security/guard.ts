import { ShieldError } from "../core/types.js";
import { checkBoundary, limitsWith, readBody } from "../http-boundary/index.js";
import { parseStrictJson } from "../http-boundary/json.js";
import { createOriginVerifier } from "./origin.js";
import { type BackendPolicy, type BackendRoute, validateBackendPolicy } from "./policy.js";

export interface BackendIdentity {
  subject: string;
}
export interface BackendContext {
  tenant: string;
  service: string;
  requestId: string;
  identity?: BackendIdentity;
  json?: unknown;
}
export interface BackendEvent {
  tenant: string;
  service: string;
  requestId: string;
  status: number;
  outcome: "allow" | "reject";
  durationMs: number;
}
export interface BackendOptions {
  policy: BackendPolicy;
  originTokens: readonly string[];
  /** Implement real token/session verification. Unverified header claims are never identities. */
  authenticate?: (
    request: Request,
    mode: "bearer" | "session",
  ) => Promise<BackendIdentity | undefined>;
  /** Must verify tenant, ownership and operation permission using authoritative application state. */
  authorize?: (
    identity: BackendIdentity,
    route: BackendRoute,
    request: Request,
  ) => Promise<boolean>;
  /** Session mutations additionally need an application-bound anti-CSRF token. */
  verifyCsrf?: (request: Request, identity: BackendIdentity) => Promise<boolean>;
  handle: (request: Request, context: BackendContext) => Promise<Response>;
  event?: (event: BackendEvent) => void;
}

/** Bounded JSON APIs only. Media, WebSockets, uploads and OAuth callbacks need separate profiles. */
export async function createBackendGuard(input: BackendOptions) {
  const options = { ...input };
  const policy = validateBackendPolicy(input.policy);
  const verifyOrigin = await createOriginVerifier(input.originTokens);
  if (
    policy.routes.some((r) => r.auth !== "public") &&
    (!options.authenticate || !options.authorize)
  )
    throw new Error("Private routes require authentication and authorization callbacks");
  if (
    policy.routes.some((r) => r.auth === "session" && r.methods.some(unsafe)) &&
    !options.verifyCsrf
  )
    throw new Error("Session mutation routes require an anti-CSRF verifier");
  const limits = limitsWith({ maxBodyBytes: policy.maxBodyBytes, bodyTimeoutMs: policy.timeoutMs });
  const routes = new Map(policy.routes.map((r) => [r.path, r]));
  let active = 0;
  return async (incoming: Request): Promise<Response> => {
    const requestId = crypto.randomUUID();
    const started = Date.now();
    const emit = (status: number, outcome: BackendEvent["outcome"]) => {
      try {
        options.event?.({
          tenant: policy.tenant,
          service: policy.service,
          requestId,
          status,
          outcome,
          durationMs: Date.now() - started,
        });
      } catch {
        /* A failed logger cannot authorize a request. */
      }
    };
    const reject = (status: number) => {
      emit(status, "reject");
      return Response.json(
        { error: "request_rejected", requestId },
        { status, headers: safeHeaders(requestId) },
      );
    };
    if (active >= policy.maxConcurrentRequests) return reject(503);
    active++;
    const abort = new AbortController();
    const onAbort = () => abort.abort();
    incoming.signal.addEventListener("abort", onAbort, { once: true });
    const operation = async () => {
      if (incoming.signal.aborted) throw new ShieldError("client-aborted", 408);
      const { url, path } = checkBoundary(incoming, limits, policy.hosts);
      if (url.protocol !== "https:") throw new ShieldError("tls-required", 400);
      if (!(await verifyOrigin(incoming))) throw new ShieldError("origin-unauthorized", 403);
      const route = routes.get(path);
      if (!route) throw new ShieldError("unknown-route", 404);
      if (!route.methods.includes(incoming.method)) throw new ShieldError("method-denied", 405);
      const bytes = await readBody(incoming, limits);
      let json: unknown;
      if (route.body === "none" && bytes.length) throw new ShieldError("unexpected-body", 400);
      if (route.body === "json" && bytes.length) {
        if (
          !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
            incoming.headers.get("content-type") ?? "",
          )
        )
          throw new ShieldError("unsupported-media", 415);
        try {
          json = parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
        } catch {
          throw new ShieldError("invalid-json", 400);
        }
      }
      const headers = new Headers(incoming.headers);
      for (const name of [...headers.keys()])
        if (
          name === "forwarded" ||
          name === "x-real-ip" ||
          name.startsWith("x-forwarded-") ||
          name.startsWith("x-shield-") ||
          name.startsWith("cf-") ||
          name.startsWith("x-vercel-") ||
          name.startsWith("x-nf-") ||
          ["host", "connection", "content-length", "transfer-encoding"].includes(name)
        )
          headers.delete(name);
      // Each callback receives a fresh bounded body so it cannot consume the business handler's body.
      const request = () =>
        new Request(url, {
          method: incoming.method,
          headers,
          signal: abort.signal,
          ...(!["GET", "HEAD"].includes(incoming.method) && bytes.length
            ? { body: bytes as BodyInit }
            : {}),
        });
      const context: BackendContext = { tenant: policy.tenant, service: policy.service, requestId };
      if (json !== undefined) context.json = json;
      if (route.auth !== "public") {
        if (
          route.auth === "bearer" &&
          !/^Bearer [\x21-\x7e]{1,2048}$/.test(headers.get("authorization") ?? "")
        )
          throw new ShieldError("bearer-required", 401);
        const identity = await options.authenticate!(request(), route.auth);
        if (
          !identity ||
          typeof identity.subject !== "string" ||
          !identity.subject.length ||
          identity.subject.length > 256
        )
          throw new ShieldError("unauthenticated", 401);
        context.identity = { subject: identity.subject };
        if (!(await options.authorize!(context.identity, structuredClone(route), request())))
          throw new ShieldError("forbidden", 403);
        if (route.auth === "session" && unsafe(incoming.method)) {
          if (
            !policy.sessionOrigins.includes(headers.get("origin") ?? "") ||
            !(await options.verifyCsrf!(request(), context.identity))
          )
            throw new ShieldError("csrf", 403);
        }
      }
      if (abort.signal.aborted) throw new ShieldError("request-timeout", 504);
      const response = await options.handle(request(), context);
      if (abort.signal.aborted) {
        void response.body?.cancel().catch(() => {});
        throw new ShieldError("request-timeout", 504);
      }
      if (response.status >= 500) {
        void response.body?.cancel().catch(() => {});
        throw new ShieldError("backend-unavailable", 503);
      }
      if (response.status >= 300 && response.status < 400 && response.status !== 304) {
        void response.body?.cancel().catch(() => {});
        throw new ShieldError("redirect-outside-json-profile", 502);
      }
      const body = response.body
        ? await readBody(
            new Request("https://response.invalid", {
              method: "POST",
              body: response.body,
              duplex: "half",
            } as RequestInit),
            limitsWith({ maxBodyBytes: 1048576, bodyTimeoutMs: policy.timeoutMs }),
          )
        : new Uint8Array();
      if (
        body.length &&
        !/^application\/json(?:\s*;[^\r\n]*)?$/i.test(response.headers.get("content-type") ?? "")
      )
        throw new ShieldError("non-json-response", 502);
      // Positive header allowlist: infrastructure names, origin credentials and CORS grants do not leak.
      const out = safeHeaders(requestId);
      if (body.length) out.set("content-type", "application/json; charset=utf-8");
      for (const cookie of response.headers.getSetCookie()) {
        if (
          !/;\s*secure(?:;|$)/i.test(cookie) ||
          !/;\s*httponly(?:;|$)/i.test(cookie) ||
          !/;\s*samesite=(?:lax|strict|none)(?:;|$)/i.test(cookie)
        )
          throw new ShieldError("insecure-backend-cookie", 502);
        out.append("set-cookie", cookie);
      }
      for (const name of ["www-authenticate", "retry-after", "allow"])
        if (response.headers.has(name)) out.set(name, response.headers.get(name)!);
      if (abort.signal.aborted) throw new ShieldError("request-timeout", 504);
      emit(response.status, "allow");
      return new Response(
        incoming.method === "HEAD" || [204, 205, 304].includes(response.status)
          ? null
          : (body as BodyInit),
        { status: response.status, headers: out },
      );
    };
    // Retain the slot until underlying work settles, even if application code ignores cancellation.
    const pending = operation().finally(() => {
      active--;
      incoming.signal.removeEventListener("abort", onAbort);
    });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        pending,
        new Promise<never>((_, rejectTimeout) => {
          timer = setTimeout(() => {
            abort.abort();
            rejectTimeout(new ShieldError("request-timeout", 504));
          }, policy.timeoutMs);
        }),
      ]);
    } catch (error) {
      return reject(error instanceof ShieldError ? error.status : 503);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
}
const unsafe = (method: string) => !["GET", "HEAD", "OPTIONS"].includes(method);
function safeHeaders(requestId: string) {
  return new Headers({
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-shield-request-id": requestId,
  });
}
