import { requireInteger } from "../core/types.js";

export interface GrpcWebProfile {
  maxMessageBytes: number;
  maxMessages: number;
  headerTimeoutMs: number;
  idleTimeoutMs: number;
  maxResponseBytes: number;
}
export function validateGrpcWebProfile(input: GrpcWebProfile): GrpcWebProfile {
  const p = structuredClone(input);
  if (
    !p ||
    Object.keys(p).some(
      (k) =>
        ![
          "maxMessageBytes",
          "maxMessages",
          "headerTimeoutMs",
          "idleTimeoutMs",
          "maxResponseBytes",
        ].includes(k),
    )
  )
    throw new Error("Invalid gRPC-Web profile");
  requireInteger(p.maxMessageBytes, 1, 16777216, "gRPC-Web message bytes");
  requireInteger(p.maxMessages, 1, 100000, "gRPC-Web messages");
  requireInteger(p.headerTimeoutMs, 1, 120000, "gRPC-Web header deadline");
  requireInteger(p.idleTimeoutMs, 1, 300000, "gRPC-Web idle deadline");
  requireInteger(p.maxResponseBytes, 1, 1073741824, "gRPC-Web response bytes");
  return p;
}

/** Binary gRPC-Web envelope inspection; native HTTP/2 framing and compressed messages are excluded. */
export function grpcWebInspector(options: {
  maxMessageBytes: number;
  maxMessages: number;
  direction: "request" | "response";
}) {
  requireInteger(options.maxMessageBytes, 1, 16777216, "gRPC-Web message bytes");
  requireInteger(options.maxMessages, 1, 100000, "gRPC-Web message count");
  const header = new Uint8Array(5);
  let headerSize = 0;
  let remaining = 0;
  let count = 0;
  let trailers = false;
  const trailerChunks: Uint8Array[] = [];
  let trailerBytes = 0;
  return (bytes: Uint8Array, final: boolean) => {
    let offset = 0;
    while (offset < bytes.length) {
      if (remaining === 0) {
        if (trailers) throw new Error("grpc-web-data-after-trailers");
        while (headerSize < 5 && offset < bytes.length) header[headerSize++] = bytes[offset++]!;
        if (headerSize < 5) break;
        const flag = header[0]!;
        if (flag !== 0 && !(flag === 128 && options.direction === "response"))
          throw new Error("grpc-web-compression-or-flags-unsupported");
        remaining = new DataView(header.buffer).getUint32(1, false);
        if (remaining > options.maxMessageBytes || ++count > options.maxMessages)
          throw new Error("grpc-web-frame-limit");
        if (options.direction === "request" && count > 1)
          throw new Error("grpc-web-request-streaming-unsupported");
        trailers = flag === 128;
        if (trailers && (remaining === 0 || remaining > 8192))
          throw new Error("grpc-web-trailers-limit");
        headerSize = 0;
        if (!remaining) continue;
      }
      const size = Math.min(remaining, bytes.length - offset);
      if (trailers && size) {
        trailerChunks.push(bytes.slice(offset, offset + size));
        trailerBytes += size;
      }
      offset += size;
      remaining -= size;
    }
    if (final) {
      if (remaining || headerSize) throw new Error("grpc-web-truncated-frame");
      if (options.direction === "request" && count !== 1)
        throw new Error("grpc-web-request-message-required");
      if (options.direction === "response") {
        if (!trailers) throw new Error("grpc-web-missing-status-trailers");
        const buffer = new Uint8Array(trailerBytes);
        let pos = 0;
        for (const chunk of trailerChunks) {
          buffer.set(chunk, pos);
          pos += chunk.length;
        }
        const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
        const lines = (text.endsWith("\r\n") ? text.slice(0, -2) : text).split("\r\n");
        const statuses = lines.filter((line) => line.startsWith("grpc-status:"));
        if (
          lines.length > 64 ||
          lines.some((line) => !/^[a-z0-9-]+: ?[\x20-\x7e]*$/.test(line)) ||
          statuses.length !== 1 ||
          !/^grpc-status: ?(?:[0-9]|1[0-6])$/.test(statuses[0]!)
        )
          throw new Error("grpc-web-invalid-status-trailers");
      }
    }
  };
}

export function protocolCapabilities() {
  return {
    media: {
      status: "implemented",
      scope: "GET/HEAD, single Range, bounded streaming; requires route profile",
    },
    websocket: {
      status: "experimental",
      scope: "authenticated handshake and message relay; platform-decoded messages only",
    },
    grpcWeb: {
      status: "experimental",
      scope:
        "binary uncompressed envelope inspector; application protobuf authorization requires a schema-aware backend",
    },
    grpc: {
      status: "unsupported",
      reason:
        "This adapter has no native HTTP/2/trailer implementation. Cloudflare announced private-beta gRPC-Web translation and Containers paths in August 2026; account access and interoperability require separate verification. An HTTP/2-aware ingress is another option.",
    },
  };
}
