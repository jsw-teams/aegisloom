import { type Fetch, requireInteger, type TrustedContext } from "../../packages/core/types.js";
import { canonicalPath } from "../../packages/http-boundary/index.js";
import {
  type MessageDirection,
  type MessageSocket,
  relayWebSockets,
  type WebSocketLimits,
  websocketLimits,
} from "../../packages/protocols/websocket.js";

declare const WebSocketPair: new () => { 0: MessageSocket; 1: MessageSocket };
interface UpgradeResponse extends Response {
  webSocket?: MessageSocket;
}
export interface CloudflareWebSocketOptions {
  tenant: string;
  engine: { inspectWebSocket(request: Request, context: TrustedContext): Promise<Response> };
  origin: string;
  allowedOrigins: string[];
  originToken: string;
  allowedBrowserOrigins: string[];
  allowMissingOrigin?: boolean;
  /** Actual platform metadata + verified auth only; no trust in incoming identity headers. */
  context: (request: Request) => Promise<Omit<TrustedContext, "tenant">>;
  maxConnections?: number;
  handshakeTimeoutMs?: number;
  limits?: Partial<WebSocketLimits>;
  inspectMessage?: (message: string | ArrayBuffer, direction: MessageDirection) => Promise<boolean>;
  fetch?: Fetch;
  /** Injection points for offline contracts; production defaults use real Cloudflare APIs. */
  pair?: () => { 0: MessageSocket; 1: MessageSocket };
  upgrade?: (socket: MessageSocket, protocol: string | null) => Response;
}
export function createCloudflareWebSocketGateway(input: CloudflareWebSocketOptions) {
  const options = { ...input, allowedBrowserOrigins: [...input.allowedBrowserOrigins] };
  const origin = new URL(options.origin);
  if (
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash ||
    !options.allowedOrigins.includes(origin.origin)
  )
    throw new Error("WebSocket upstream must be an exact allowlisted HTTPS origin");
  if (
    !/^[\x21-\x7e]{32,2048}$/.test(options.originToken) ||
    !/^[A-Za-z0-9_-]{1,64}$/.test(options.tenant)
  )
    throw new Error("Invalid WebSocket origin secret or tenant");
  for (const value of options.allowedBrowserOrigins) {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.origin !== value)
      throw new Error("Browser origins must be exact HTTPS origins");
  }
  const maxConnections = requireInteger(
    options.maxConnections ?? 64,
    1,
    256,
    "WebSocket connections",
  );
  const timeoutMs = requireInteger(
    options.handshakeTimeoutMs ?? 5000,
    1,
    30000,
    "WebSocket handshake timeout",
  );
  const limits = websocketLimits(options.limits);
  const transport = options.fetch ?? fetch;
  let active = 0;
  const reply = (status: number) =>
    Response.json(
      { error: "websocket_rejected" },
      { status, headers: { "cache-control": "no-store" } },
    );
  return async (request: Request): Promise<Response> => {
    if (active >= maxConnections) return reply(503);
    active++;
    let released = false;
    let upgraded = false;
    const release = () => {
      if (!released) {
        released = true;
        active--;
      }
    };
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let originSocket: MessageSocket | undefined;
    const operation = async () => {
      const browserOrigin = request.headers.get("origin");
      if (
        (browserOrigin === null && !options.allowMissingOrigin) ||
        (browserOrigin !== null && !options.allowedBrowserOrigins.includes(browserOrigin))
      )
        return reply(403);
      const verified = await options.context(request);
      if (abort.signal.aborted) return reply(504);
      const decision = await options.engine.inspectWebSocket(request, {
        ...verified,
        tenant: options.tenant,
      });
      if (decision.status !== 204) return decision;
      if (abort.signal.aborted) return reply(504);
      const target = new URL(origin);
      const url = new URL(request.url);
      target.pathname = canonicalPath(url.pathname);
      target.search = url.search;
      const headers = new Headers(request.headers);
      for (const name of [...headers.keys()])
        if (
          name === "forwarded" ||
          name === "x-real-ip" ||
          name.startsWith("x-forwarded-") ||
          name.startsWith("x-shield-") ||
          name.startsWith("cf-") ||
          name.startsWith("x-vercel-") ||
          name.startsWith("x-nf-") ||
          [
            "host",
            "connection",
            "content-length",
            "transfer-encoding",
            "sec-websocket-extensions",
          ].includes(name)
        )
          headers.delete(name);
      headers.set("upgrade", "websocket");
      headers.set("x-shield-origin-auth", options.originToken);
      const response = (await transport(target, {
        method: "GET",
        headers,
        redirect: "manual",
        signal: abort.signal,
      })) as UpgradeResponse;
      originSocket = response.webSocket;
      if (
        abort.signal.aborted ||
        response.status !== 101 ||
        !originSocket ||
        response.headers.has("sec-websocket-extensions")
      ) {
        try {
          originSocket?.close(1008, "upgrade rejected");
        } catch {
          /* Unaccepted socket. */
        }
        void response.body?.cancel().catch(() => {});
        return reply(abort.signal.aborted ? 504 : 502);
      }
      const selected = response.headers.get("sec-websocket-protocol");
      const offered = (request.headers.get("sec-websocket-protocol") ?? "")
        .split(",")
        .map((v) => v.trim());
      if (
        selected &&
        (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(selected) || !offered.includes(selected))
      ) {
        originSocket.close(1008, "protocol rejected");
        return reply(502);
      }
      const pair = options.pair?.() ?? new WebSocketPair();
      const responseToClient = options.upgrade
        ? options.upgrade(pair[0], selected)
        : new Response(null, {
            status: 101,
            webSocket: pair[0],
            headers: selected ? { "sec-websocket-protocol": selected } : {},
          } as ResponseInit);
      relayWebSockets(pair[1], originSocket, {
        limits,
        ...(options.inspectMessage ? { inspect: options.inspectMessage } : {}),
        closed: release,
      });
      upgraded = true;
      return responseToClient;
    };
    // Admission includes pending handshakes. A stuck auth callback retains its slot until settled.
    const pending = operation().finally(() => {
      if (!upgraded) release();
    });
    try {
      return await Promise.race([
        pending,
        new Promise<Response>((resolve) => {
          timer = setTimeout(() => {
            abort.abort();
            resolve(reply(504));
          }, timeoutMs);
        }),
      ]);
    } catch {
      try {
        originSocket?.close(1011, "gateway unavailable");
      } catch {
        /* Already closed. */
      }
      return reply(502);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
}
