import { requireInteger, ShieldError } from "../core/types.js";

export interface BoundaryLimits {
  maxBodyBytes: number;
  maxUrlBytes: number;
  maxHeaderBytes: number;
  maxHeaders: number;
  bodyTimeoutMs: number;
}
export const defaultLimits: BoundaryLimits = {
  maxBodyBytes: 262144,
  maxUrlBytes: 8192,
  maxHeaderBytes: 16384,
  maxHeaders: 64,
  bodyTimeoutMs: 5000,
};

export function limitsWith(input: Partial<BoundaryLimits> = {}): BoundaryLimits {
  const limits = { ...defaultLimits, ...input };
  requireInteger(limits.maxBodyBytes, 0, 16_777_216, "maxBodyBytes");
  requireInteger(limits.maxUrlBytes, 256, 65536, "maxUrlBytes");
  requireInteger(limits.maxHeaderBytes, 256, 65536, "maxHeaderBytes");
  requireInteger(limits.maxHeaders, 1, 256, "maxHeaders");
  requireInteger(limits.bodyTimeoutMs, 1, 60000, "bodyTimeoutMs");
  return limits;
}

/** Must run BEFORE constructing a URL/Request when the host exposes the original target. */
export function canonicalPath(target: string): string {
  const path = target.split("?", 1)[0] ?? "";
  if (!path.startsWith("/") || path.startsWith("//") || /[\\;#\u0000-\u0020\u007f]/.test(path))
    throw new ShieldError("ambiguous-path");
  if (/%(?:2f|5c|25|2e|00|3f|23|3b)/i.test(path)) throw new ShieldError("ambiguous-path-encoding");
  let decoded: string;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    throw new ShieldError("invalid-path-encoding");
  }
  if (
    decoded.includes("//") ||
    /(?:^|\/)\.{1,2}(?:\/|$)/.test(decoded) ||
    /[\\;#?\u0000-\u0020\u007f]/.test(decoded) ||
    decoded !== decoded.normalize("NFC")
  )
    throw new ShieldError("ambiguous-path");
  return decoded;
}

/** Raw framing inspection is available ONLY to the local Node adapter, not to Web Request. */
export function checkRawHeaders(raw: readonly string[]): void {
  if (raw.length > 128) throw new ShieldError("too-many-raw-headers", 431);
  const seen = new Set<string>();
  for (let i = 0; i < raw.length; i += 2) {
    const name = (raw[i] ?? "").toLowerCase();
    const value = raw[i + 1] ?? "";
    if (
      !/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) ||
      /[\u0000-\u0008\u000a-\u001f\u007f]/.test(value)
    )
      throw new ShieldError("invalid-raw-header");
    if (
      seen.has(name) &&
      ["host", "content-length", "transfer-encoding", "authorization"].includes(name)
    )
      throw new ShieldError("duplicate-security-header");
    seen.add(name);
  }
  if (seen.has("content-length") && seen.has("transfer-encoding"))
    throw new ShieldError("ambiguous-framing");
}

export function checkBoundary(
  request: Request,
  limits: BoundaryLimits,
  publicHosts: readonly string[],
  rawTarget?: string,
  protocol: "http" | "websocket" = "http",
): { url: URL; path: string } {
  if (new TextEncoder().encode(request.url).length > limits.maxUrlBytes)
    throw new ShieldError("url-too-large", 414);
  const url = new URL(request.url);
  if (
    !["https:", "http:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    !publicHosts.includes(url.host)
  )
    throw new ShieldError("untrusted-host", 421);
  if (request.headers.has("host") && request.headers.get("host") !== url.host)
    throw new ShieldError("host-mismatch", 421);
  if (rawTarget !== undefined) canonicalPath(rawTarget);
  const path = canonicalPath(url.pathname);
  try {
    decodeURIComponent(url.search);
  } catch {
    throw new ShieldError("invalid-query-encoding");
  }
  if ([...url.searchParams].length > 128) throw new ShieldError("too-many-query-fields");
  let headerBytes = 0;
  let headerCount = 0;
  for (const [name, value] of request.headers) {
    headerCount++;
    headerBytes += new TextEncoder().encode(name + value).length + 4;
    if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(value)) throw new ShieldError("invalid-header");
  }
  if (headerBytes > limits.maxHeaderBytes || headerCount > limits.maxHeaders)
    throw new ShieldError("headers-too-large", 431);
  const cl = request.headers.get("content-length");
  const te = request.headers.get("transfer-encoding");
  if (request.headers.has("expect") || request.headers.has("trailer"))
    throw new ShieldError("unsupported-expect-or-trailers", 417);
  if (["GET", "HEAD"].includes(request.method) && (te !== null || Number(cl ?? "0") > 0))
    throw new ShieldError("body-not-allowed-for-method");
  if (te && (cl !== null || te.toLowerCase() !== "chunked"))
    throw new ShieldError("ambiguous-framing");
  if (cl !== null && (!/^(0|[1-9][0-9]*)$/.test(cl) || !Number.isSafeInteger(Number(cl))))
    throw new ShieldError("invalid-content-length");
  if (cl !== null && Number(cl) > limits.maxBodyBytes) throw new ShieldError("body-too-large", 413);
  const connection = request.headers.get("connection");
  if (
    connection
      ?.split(",")
      .some(
        (s) =>
          !(protocol === "websocket" ? ["upgrade"] : ["close", "keep-alive"]).includes(
            s.trim().toLowerCase(),
          ),
      )
  )
    throw new ShieldError("unsafe-connection-header");
  if (protocol === "websocket") {
    if (
      request.method !== "GET" ||
      request.headers.get("upgrade")?.toLowerCase() !== "websocket" ||
      request.headers.get("sec-websocket-version") !== "13" ||
      !/^[A-Za-z0-9+/]{22}==$/.test(request.headers.get("sec-websocket-key") ?? "")
    )
      throw new ShieldError("invalid-or-unsupported-websocket-handshake", 400);
  }
  if (
    (protocol !== "websocket" && request.headers.has("upgrade")) ||
    request.method === "CONNECT" ||
    request.method === "TRACE"
  )
    throw new ShieldError("unsupported-protocol", 405);
  if (
    request.headers.has("content-encoding") &&
    request.headers.get("content-encoding") !== "identity"
  )
    throw new ShieldError("unsupported-content-encoding", 415);
  if (request.headers.get("content-type")?.toLowerCase().startsWith("multipart/"))
    throw new ShieldError("multipart-requires-native-parser", 415);
  return { url, path };
}

export async function readBody(request: Request, limits: BoundaryLimits): Promise<Uint8Array> {
  if (!request.body) {
    if (Number(request.headers.get("content-length") ?? "0") !== 0)
      throw new ShieldError("body-length-mismatch");
    return new Uint8Array();
  }
  const reader = request.body.getReader();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new ShieldError("body-timeout", 408)), limits.bodyTimeoutMs);
    });
    await Promise.race([
      (async () => {
        while (true) {
          const item = await reader.read();
          if (item.done) break;
          size += item.value.byteLength;
          if (size > limits.maxBodyBytes) throw new ShieldError("body-too-large", 413);
          chunks.push(item.value.slice());
        }
      })(),
      timeout,
    ]);
  } catch (error) {
    void reader.cancel().catch(() => {});
    throw error;
  } finally {
    if (timer) clearTimeout(timer);
  }
  const cl = request.headers.get("content-length");
  if (cl !== null && Number(cl) !== size) throw new ShieldError("body-length-mismatch");
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}
