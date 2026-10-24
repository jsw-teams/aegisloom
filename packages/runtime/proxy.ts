import { type Fetch, requireInteger, ShieldError } from "../core/types.js";
import { type GrpcWebProfile, grpcWebInspector } from "../protocols/grpc.js";
import { type MediaProfile, protectStream, validateRange } from "../protocols/stream.js";

export interface ProxyOptions {
  origin: string;
  allowedOrigins: readonly string[];
  originToken: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  allowLoopbackHttp?: boolean;
  fetch?: Fetch;
}
const hop = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
];

export function createProxy(options: ProxyOptions) {
  const origin = new URL(options.origin);
  const loopback = ["127.0.0.1", "[::1]"].includes(origin.hostname);
  if (
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash ||
    !options.allowedOrigins.includes(origin.origin)
  )
    throw new Error("Origin must be an exact allowlisted origin without credentials/path/query");
  if (
    origin.protocol !== "https:" &&
    !(options.allowLoopbackHttp && loopback && origin.protocol === "http:")
  )
    throw new Error("Upstream TLS required (only explicit loopback development HTTP allowed)");
  const originToken = options.originToken;
  if (!/^[\x21-\x7e]{32,2048}$/.test(originToken))
    throw new Error("Origin authentication token must contain 32..2048 visible ASCII characters");
  const timeout = requireInteger(options.timeoutMs ?? 10000, 1, 120000, "proxy timeout");
  const maxResponse = requireInteger(
    options.maxResponseBytes ?? 16777216,
    1,
    1073741824,
    "response bytes",
  );
  const transport = options.fetch ?? fetch;
  let consecutiveFailures = 0;
  let openUntil = 0;
  return async (
    incoming: Request,
    url: URL,
    path: string,
    body: Uint8Array,
    onComplete: () => void = () => {},
    media?: MediaProfile,
    grpcWeb?: GrpcWebProfile,
  ): Promise<Response> => {
    if (Date.now() < openUntil) throw new ShieldError("origin-circuit-open", 503);
    if (media) {
      if (!["GET", "HEAD"].includes(incoming.method) || body.length)
        throw new ShieldError("media-method-or-body", 405);
      try {
        validateRange(incoming.headers.get("range"));
      } catch {
        throw new ShieldError("invalid-media-range", 416);
      }
    }
    const target = new URL(origin);
    target.pathname = path;
    target.search = url.search;
    if (target.origin !== origin.origin) throw new ShieldError("origin-allowlist", 502);
    const headers = new Headers(incoming.headers);
    for (const name of [...headers.keys()]) {
      if (
        hop.includes(name) ||
        name === "forwarded" ||
        name === "x-real-ip" ||
        name.startsWith("x-forwarded-") ||
        name.startsWith("cf-") ||
        name.startsWith("x-vercel-") ||
        name.startsWith("x-nf-") ||
        name.startsWith("x-shield-")
      )
        headers.delete(name);
    }
    headers.set("x-shield-origin-auth", originToken);
    headers.set("accept-encoding", "identity");
    const abort = new AbortController();
    let completed = false;
    const timer = setTimeout(
      () => {
        abort.abort();
        cleanup();
      },
      media?.headerTimeoutMs ?? grpcWeb?.headerTimeoutMs ?? timeout,
    );
    const abortFromClient = () => abort.abort();
    incoming.signal.addEventListener("abort", abortFromClient, { once: true });
    const cleanup = () => {
      if (completed) return;
      completed = true;
      clearTimeout(timer);
      incoming.signal.removeEventListener("abort", abortFromClient);
      onComplete();
    };
    try {
      const init: RequestInit = {
        method: incoming.method,
        headers,
        redirect: "manual",
        signal: abort.signal,
      };
      if (!["GET", "HEAD"].includes(incoming.method) && body.length) init.body = body as BodyInit;
      if (incoming.signal.aborted) throw new ShieldError("client-aborted", 408);
      const upstream = await transport(target, init);
      if (abort.signal.aborted) {
        void upstream.body?.cancel().catch(() => {});
        throw new ShieldError("origin-timeout-or-abort", 504);
      }
      if (media || grpcWeb) clearTimeout(timer);
      if (
        grpcWeb &&
        (upstream.status !== 200 ||
          !["application/grpc-web", "application/grpc-web+proto"].includes(
            (upstream.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase(),
          ) ||
          (upstream.headers.has("grpc-encoding") &&
            upstream.headers.get("grpc-encoding") !== "identity"))
      ) {
        void upstream.body?.cancel().catch(() => {});
        throw new ShieldError("unsupported-grpc-web-origin", 502);
      }
      if (grpcWeb && !upstream.body) throw new ShieldError("grpc-web-missing-trailers", 502);
      if (media) {
        clearTimeout(timer);
        if (![200, 206, 304, 416].includes(upstream.status)) {
          void upstream.body?.cancel().catch(() => {});
          throw new ShieldError("media-origin-status", 502);
        }
        if (
          upstream.body &&
          ![304, 416].includes(upstream.status) &&
          !media.contentTypes.includes(
            (upstream.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase(),
          )
        ) {
          void upstream.body?.cancel().catch(() => {});
          throw new ShieldError("media-content-type", 502);
        }
        if (
          upstream.status === 206 &&
          !/^bytes [0-9]+-[0-9]+\/(?:[0-9]+|\*)$/.test(upstream.headers.get("content-range") ?? "")
        ) {
          void upstream.body?.cancel().catch(() => {});
          throw new ShieldError("media-content-range", 502);
        }
      }
      if (upstream.status >= 500) {
        consecutiveFailures++;
        if (consecutiveFailures >= 5) openUntil = Date.now() + 5000;
      } else consecutiveFailures = 0;
      // Avoid fetch implementations disagreeing about automatic decompression.
      if (
        upstream.headers.has("content-encoding") &&
        upstream.headers.get("content-encoding") !== "identity"
      ) {
        void upstream.body?.cancel().catch(() => {});
        throw new ShieldError("unexpected-origin-encoding", 502);
      }
      const responseHeaders = new Headers(upstream.headers);
      for (const token of (responseHeaders.get("connection") ?? "").split(","))
        if (token.trim()) responseHeaders.delete(token.trim());
      for (const name of [...responseHeaders.keys()])
        if (
          hop.includes(name) ||
          ["server", "x-powered-by"].includes(name) ||
          name.startsWith("x-shield-")
        )
          responseHeaders.delete(name);
      responseHeaders.set("cache-control", "no-store");
      if (
        !upstream.body ||
        incoming.method === "HEAD" ||
        [204, 205, 304].includes(upstream.status)
      ) {
        cleanup();
        void upstream.body?.cancel().catch(() => {});
        return new Response(null, { status: upstream.status, headers: responseHeaders });
      }
      const stream = protectStream(upstream.body, {
        maxBytes: media?.maxBytes ?? grpcWeb?.maxResponseBytes ?? maxResponse,
        idleTimeoutMs: media?.idleTimeoutMs ?? grpcWeb?.idleTimeoutMs ?? timeout,
        signal: abort.signal,
        abort: () => abort.abort(),
        complete: cleanup,
        ...(grpcWeb ? { inspect: grpcWebInspector({ ...grpcWeb, direction: "response" }) } : {}),
      });
      return new Response(stream, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: responseHeaders,
      });
    } catch (error) {
      const wasAborted = abort.signal.aborted;
      cleanup();
      abort.abort();
      consecutiveFailures++;
      if (consecutiveFailures >= 5) openUntil = Date.now() + 5000;
      if (error instanceof ShieldError) throw error;
      throw new ShieldError(
        wasAborted ? "origin-timeout-or-abort" : "origin-unavailable",
        wasAborted ? 504 : 502,
      );
    }
  };
}
