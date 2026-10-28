import { stableJson } from "../core/types.js";
export interface ReplayStore {
  claim(id: string, expiresAt: number): Promise<boolean>;
}
const encoder = new TextEncoder(),
  decoder = new TextDecoder("utf-8", { fatal: true });
const bytes = (value: Uint8Array) => value as BufferSource;
function b64(value: Uint8Array) {
  let text = "";
  for (let i = 0; i < value.length; i += 8192)
    text += String.fromCharCode(...value.subarray(i, i + 8192));
  return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
function unb64(value: string, limit: number) {
  if (
    typeof value !== "string" ||
    value.length > Math.ceil((limit * 4) / 3) + 4 ||
    !/^[\w-]*$/.test(value)
  )
    throw new Error("Invalid relay encoding");
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
  if (binary.length > limit) throw new Error("Relay value exceeds limit");
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}
async function readBytes(response: Response | Request, limit: number) {
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader(),
    chunks: Uint8Array[] = [];
  let length = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("Relay read deadline exceeded")), 10000);
  });
  try {
    while (true) {
      const item = await Promise.race([reader.read(), timeout]);
      if (item.done) break;
      length += item.value.length;
      if (length > limit) throw new Error("Relay body exceeds limit");
      chunks.push(item.value);
    }
  } catch (error) {
    void reader.cancel().catch(() => {});
    throw error;
  } finally {
    clearTimeout(timer);
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}
function bodyLimit(value: number | undefined) {
  const limit = value ?? 8 * 1024 * 1024;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 16 * 1024 * 1024)
    throw new Error("Relay byte limit must be 1..16777216");
  return limit;
}
function exact(value: string, length: number) {
  const decoded = unb64(value, length);
  if (decoded.length !== length) throw new Error("Invalid relay field length");
  return decoded;
}
async function macKey(secret: string) {
  if (!/^[\w-]{43,256}$/.test(secret))
    throw new Error("Relay authentication key must be random base64url");
  return crypto.subtle.importKey(
    "raw",
    bytes(unb64(secret, 192)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}
async function publicKey(jwk: JsonWebKey) {
  if (jwk?.kty !== "EC" || jwk.crv !== "P-256" || jwk.d !== undefined)
    throw new Error("Relay requires a public P-256 key");
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, []);
}
async function keys(privateKey: CryptoKey, publicKey: CryptoKey, salt: Uint8Array) {
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256,
  );
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const derive = (direction: string) =>
    crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: bytes(salt),
        info: bytes(encoder.encode(`edgeshield-relay:v1:${direction}`)),
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  return { request: await derive("request"), response: await derive("response") };
}
function headers(input: Headers) {
  return [...input]
    .filter(([key]) => key !== "set-cookie")
    .concat(input.getSetCookie().map((value) => ["set-cookie", value] as [string, string]));
}
export async function createRelayTransport(options: {
  endpoint: string;
  serverPublicKey: JsonWebKey;
  authenticationKey: string;
  maxBytes?: number;
  fetch?: typeof fetch;
  now?: () => number;
}) {
  const endpoint = new URL(options.endpoint);
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.hash)
    throw new Error("Relay requires an exact HTTPS endpoint");
  const server = await publicKey(options.serverPublicKey),
    authentication = await macKey(options.authenticationKey),
    limit = bodyLimit(options.maxBytes),
    transport = options.fetch ?? fetch,
    now = options.now ?? Date.now;
  return async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init),
      target = new URL(request.url);
    if (target.origin !== "https://origin.internal")
      throw new Error("Relay target is outside the private business origin");
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
      "deriveBits",
    ]);
    const salt = crypto.getRandomValues(new Uint8Array(32)),
      session = await keys(pair.privateKey, server, salt);
    const meta = {
      v: 1,
      id: crypto.randomUUID(),
      at: now(),
      epk: await crypto.subtle.exportKey("jwk", pair.publicKey),
      salt: b64(salt),
    };
    const aad = encoder.encode(stableJson(meta)),
      nonce = crypto.getRandomValues(new Uint8Array(12));
    const plain = encoder.encode(
      JSON.stringify({
        method: request.method,
        target: target.pathname + target.search,
        headers: headers(request.headers),
        body: b64(await readBytes(request, limit)),
      }),
    );
    if (plain.length > limit * 2 + 65536) throw new Error("Relay payload exceeds limit");
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: bytes(nonce), additionalData: bytes(aad) },
        session.request,
        bytes(plain),
      ),
    );
    const packet = { ...meta, nonce: b64(nonce), body: b64(ciphertext) };
    const signature = b64(
      new Uint8Array(
        await crypto.subtle.sign("HMAC", authentication, bytes(encoder.encode(stableJson(packet)))),
      ),
    );
    const response = await transport(endpoint, {
      method: "POST",
      redirect: "manual",
      signal: request.signal,
      headers: { "content-type": "application/vnd.edgeshield.relay+json" },
      body: JSON.stringify({ ...packet, signature }),
    });
    if (!response.ok) throw new Error(`Relay endpoint rejected request (${response.status})`);
    const envelope = JSON.parse(decoder.decode(await readBytes(response, limit * 3 + 262144)));
    if (envelope.v !== 1 || envelope.id !== meta.id)
      throw new Error("Relay response binding mismatch");
    const decoded = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: bytes(exact(envelope.nonce, 12)),
        additionalData: bytes(
          encoder.encode(stableJson({ v: 1, id: meta.id, direction: "response" })),
        ),
      },
      session.response,
      bytes(unb64(envelope.body, limit * 2 + 65536)),
    );
    const result = JSON.parse(decoder.decode(decoded));
    if (
      !Number.isInteger(result.status) ||
      result.status < 200 ||
      result.status > 599 ||
      !Array.isArray(result.headers)
    )
      throw new Error("Invalid relay response");
    const body = unb64(result.body, limit);
    return new Response(
      request.method === "HEAD" || [204, 205, 304].includes(result.status)
        ? null
        : (body as BodyInit),
      { status: result.status, headers: result.headers },
    );
  };
}
export async function createRelayServer(options: {
  serverPrivateKey: JsonWebKey;
  authenticationKey: string;
  originToken: string;
  business: (request: Request) => Promise<Response>;
  replay: ReplayStore;
  maxBytes?: number;
  now?: () => number;
}) {
  const privateKey = await crypto.subtle.importKey(
      "jwk",
      options.serverPrivateKey,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    ),
    authentication = await macKey(options.authenticationKey),
    limit = bodyLimit(options.maxBytes),
    now = options.now ?? Date.now;
  return async (request: Request) => {
    try {
      if (request.method !== "POST") return new Response(null, { status: 405 });
      const packet = JSON.parse(decoder.decode(await readBytes(request, limit * 3 + 262144)));
      const { signature, ...signed } = packet;
      if (
        packet.v !== 1 ||
        typeof packet.id !== "string" ||
        !/^[a-f\d-]{36}$/i.test(packet.id) ||
        !Number.isSafeInteger(packet.at) ||
        Math.abs(now() - packet.at) > 30000 ||
        Object.keys(packet).some(
          (key) => !["v", "id", "at", "epk", "salt", "nonce", "body", "signature"].includes(key),
        )
      )
        throw new Error("Invalid relay envelope");
      if (
        !(await crypto.subtle.verify(
          "HMAC",
          authentication,
          bytes(exact(signature, 32)),
          bytes(encoder.encode(stableJson(signed))),
        ))
      )
        throw new Error("Relay authentication failed");
      if (!(await options.replay.claim(packet.id, packet.at + 60000)))
        throw new Error("Relay request replayed");
      const meta = { v: 1, id: packet.id, at: packet.at, epk: packet.epk, salt: packet.salt },
        session = await keys(privateKey, await publicKey(packet.epk), exact(packet.salt, 32));
      const plain = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: bytes(exact(packet.nonce, 12)),
          additionalData: bytes(encoder.encode(stableJson(meta))),
        },
        session.request,
        bytes(unb64(packet.body, limit * 2 + 65536)),
      );
      const decoded = JSON.parse(decoder.decode(plain));
      if (
        typeof decoded.method !== "string" ||
        !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(decoded.method) ||
        typeof decoded.target !== "string" ||
        !decoded.target.startsWith("/") ||
        decoded.target.startsWith("//") ||
        /[\r\n#]/.test(decoded.target) ||
        !Array.isArray(decoded.headers) ||
        decoded.headers.length > 128
      )
        throw new Error("Invalid relay request target");
      const target = new URL(decoded.target, "https://origin.internal");
      if (target.origin !== "https://origin.internal") throw new Error("Invalid relay authority");
      const payload = unb64(decoded.body, limit),
        requestHeaders = new Headers(decoded.headers);
      const expected = await crypto.subtle.digest(
          "SHA-256",
          bytes(encoder.encode(options.originToken)),
        ),
        provided = await crypto.subtle.digest(
          "SHA-256",
          bytes(encoder.encode(requestHeaders.get("x-shield-origin-auth") ?? "")),
        );
      if (b64(new Uint8Array(expected)) !== b64(new Uint8Array(provided)))
        throw new Error("Untrusted relay origin credential");
      const response = await options.business(
        new Request(target, {
          method: decoded.method,
          headers: requestHeaders,
          ...(!["GET", "HEAD"].includes(decoded.method) && payload.length
            ? { body: payload as BodyInit }
            : {}),
        }),
      );
      const body = encoder.encode(
        JSON.stringify({
          status: response.status,
          headers: headers(response.headers),
          body: b64(await readBytes(response, limit)),
        }),
      );
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const cipher = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: bytes(nonce),
          additionalData: bytes(
            encoder.encode(stableJson({ v: 1, id: packet.id, direction: "response" })),
          ),
        },
        session.response,
        bytes(body),
      );
      return Response.json(
        { v: 1, id: packet.id, nonce: b64(nonce), body: b64(new Uint8Array(cipher)) },
        { headers: { "cache-control": "no-store" } },
      );
    } catch {
      return Response.json(
        { error: "relay_request_rejected" },
        { status: 403, headers: { "cache-control": "no-store" } },
      );
    }
  };
}
