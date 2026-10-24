import { requireInteger } from "../core/types.js";

/** Cloudflare WebSockets expose decoded messages, not masking, fragments or HTTP/2 frames. */
export interface MessageSocket {
  binaryType?: string;
  accept(options?: { allowHalfOpen?: boolean }): void;
  send(message: string | ArrayBuffer | ArrayBufferView): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: "message", callback: (event: { data: unknown }) => void): void;
  addEventListener(type: "close" | "error", callback: () => void): void;
}
export interface WebSocketLimits {
  maxMessageBytes: number;
  maxSessionBytes: number;
  maxMessagesPerWindow: number;
  windowMs: number;
  maxQueuedMessages: number;
  maxQueuedBytes: number;
  idleTimeoutMs: number;
  maxLifetimeMs: number;
  inspectionTimeoutMs: number;
}
export const defaultWebSocketLimits: WebSocketLimits = {
  maxMessageBytes: 65536,
  maxSessionBytes: 16777216,
  maxMessagesPerWindow: 100,
  windowMs: 1000,
  maxQueuedMessages: 16,
  maxQueuedBytes: 1048576,
  idleTimeoutMs: 30000,
  maxLifetimeMs: 300000,
  inspectionTimeoutMs: 100,
};
export function websocketLimits(input: Partial<WebSocketLimits> = {}): WebSocketLimits {
  if (Object.keys(input).some((k) => !(k in defaultWebSocketLimits)))
    throw new Error("Unknown WebSocket limit");
  const p = { ...defaultWebSocketLimits, ...input };
  requireInteger(p.maxMessageBytes, 1, 1048576, "WebSocket message bytes");
  requireInteger(p.maxSessionBytes, 1, 67108864, "WebSocket session bytes");
  requireInteger(p.maxMessagesPerWindow, 1, 10000, "WebSocket message rate");
  requireInteger(p.windowMs, 10, 60000, "WebSocket rate window");
  requireInteger(p.maxQueuedMessages, 1, 256, "WebSocket queued messages");
  requireInteger(p.maxQueuedBytes, 1, 4194304, "WebSocket queued bytes");
  requireInteger(p.idleTimeoutMs, 1, 300000, "WebSocket idle deadline");
  requireInteger(p.maxLifetimeMs, 1, 3600000, "WebSocket lifetime");
  requireInteger(p.inspectionTimeoutMs, 1, 5000, "WebSocket inspection deadline");
  return p;
}
export type MessageDirection = "client-to-origin" | "origin-to-client";
export function relayWebSockets(
  client: MessageSocket,
  origin: MessageSocket,
  options: {
    limits?: Partial<WebSocketLimits>;
    inspect?: (message: string | ArrayBuffer, direction: MessageDirection) => Promise<boolean>;
    closed?: () => void;
  },
) {
  const limits = websocketLimits(options.limits);
  let ended = false;
  let total = 0;
  let idle: ReturnType<typeof setTimeout>;
  let lifetime: ReturnType<typeof setTimeout>;
  const inspectionTimers = new Set<ReturnType<typeof setTimeout>>();
  const inspectionCancellations = new Set<() => void>();
  const queues: { data: string | ArrayBuffer; bytes: number }[][] = [];
  const finish = (code = 1000, reason = "connection closed") => {
    if (ended) return;
    ended = true;
    clearTimeout(idle);
    clearTimeout(lifetime);
    for (const timer of inspectionTimers) clearTimeout(timer);
    for (const cancel of inspectionCancellations) cancel();
    for (const queue of queues) queue.length = 0;
    for (const socket of [client, origin]) {
      try {
        socket.close(code, reason);
      } catch {
        /* Already closed. */
      }
    }
    try {
      options.closed?.();
    } catch {
      /* Cleanup cannot reopen a closed session. */
    }
  };
  const resetIdle = () => {
    clearTimeout(idle);
    idle = setTimeout(() => finish(1008, "idle limit"), limits.idleTimeoutMs);
  };
  for (const [from, to, direction] of [
    [client, origin, "client-to-origin"],
    [origin, client, "origin-to-client"],
  ] as const) {
    const queue: { data: string | ArrayBuffer; bytes: number }[] = [];
    queues.push(queue);
    let queuedBytes = 0;
    let busy = false;
    // Token bucket avoids a double burst at a fixed-window boundary.
    let tokens = limits.maxMessagesPerWindow;
    let refilledAt = Date.now();
    const drain = async () => {
      if (busy) return;
      busy = true;
      try {
        while (!ended && queue.length) {
          const item = queue[0]!;
          if (options.inspect) {
            let timer: ReturnType<typeof setTimeout> | undefined;
            let cancel: (() => void) | undefined;
            try {
              const accepted = await Promise.race([
                options.inspect(item.data, direction),
                new Promise<boolean>((resolve) => {
                  cancel = () => resolve(false);
                  inspectionCancellations.add(cancel);
                  timer = setTimeout(() => resolve(false), limits.inspectionTimeoutMs);
                  inspectionTimers.add(timer);
                }),
              ]);
              if (!accepted) {
                finish(1008, "message policy");
                return;
              }
            } finally {
              if (timer) {
                clearTimeout(timer);
                inspectionTimers.delete(timer);
              }
              if (cancel) inspectionCancellations.delete(cancel);
            }
          }
          if (ended) return;
          to.send(item.data);
          queue.shift();
          queuedBytes -= item.bytes;
        }
      } catch {
        finish(1011, "relay unavailable");
      } finally {
        busy = false;
      }
    };
    from.addEventListener("message", (event) => {
      if (ended) return;
      let data: string | ArrayBuffer;
      let size: number;
      if (typeof event.data === "string") {
        if (event.data.length > limits.maxMessageBytes) {
          finish(1009, "message size");
          return;
        }
        size = new TextEncoder().encode(event.data).byteLength;
        data = event.data;
      } else if (event.data instanceof ArrayBuffer) {
        size = event.data.byteLength;
        if (size > limits.maxMessageBytes) {
          finish(1009, "message size");
          return;
        }
        data = event.data.slice(0);
      } else {
        finish(1003, "unsupported message");
        return;
      }
      const now = Date.now();
      tokens = Math.min(
        limits.maxMessagesPerWindow,
        tokens + (Math.max(0, now - refilledAt) * limits.maxMessagesPerWindow) / limits.windowMs,
      );
      refilledAt = now;
      if (tokens < 1) {
        finish(1008, "message rate");
        return;
      }
      tokens--;
      total += size;
      if (size > limits.maxMessageBytes || total > limits.maxSessionBytes) {
        finish(1009, "transfer size");
        return;
      }
      if (queue.length >= limits.maxQueuedMessages || queuedBytes + size > limits.maxQueuedBytes) {
        finish(1008, "inspection queue");
        return;
      }
      queuedBytes += size;
      queue.push({ data, bytes: size });
      resetIdle();
      void drain();
    });
    from.addEventListener("close", () => finish());
    from.addEventListener("error", () => finish(1011, "connection unavailable"));
  }
  try {
    // Newer Workers dates default to Blob; fix the representation before message dispatch.
    client.binaryType = "arraybuffer";
    origin.binaryType = "arraybuffer";
    client.accept({ allowHalfOpen: true });
    origin.accept({ allowHalfOpen: true });
    resetIdle();
    lifetime = setTimeout(() => finish(1008, "lifetime limit"), limits.maxLifetimeMs);
  } catch {
    finish(1011, "accept unavailable");
  }
  return { close: () => finish(1001, "operator close") };
}
