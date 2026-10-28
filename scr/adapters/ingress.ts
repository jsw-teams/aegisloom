import ipaddr from "ipaddr.js";
import type { TrustedContext } from "../core/types.js";
import { stableJson } from "../core/types.js";

export type IngressMetadata = Omit<TrustedContext, "tenant" | "identity"> & {
  originalUrl?: string;
  rawTarget?: string;
};
type Metadata = IngressMetadata;
const encoder = new TextEncoder();
async function key(secret: string) {
  if (!/^[\w-]{43,256}$/.test(secret)) throw new Error("Invalid ingress signing key");
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}
function message(request: Request, metadata: Metadata, at: number) {
  return encoder.encode(stableJson({ method: request.method, url: request.url, metadata, at }));
}
function validate(value: Metadata) {
  if (
    !/^HTTP\/(?:1\.0|1\.1|2(?:\.0)?|3(?:\.0)?)$/.test(value.httpProtocol ?? "") ||
    !value.verifiedClientIp ||
    !ipaddr.isValid(value.verifiedClientIp) ||
    Object.keys(value).some(
      (k) => !["httpProtocol", "verifiedClientIp", "originalUrl", "rawTarget"].includes(k),
    )
  )
    throw new Error("Actual ingress protocol and IP are required");
  if (value.originalUrl !== undefined) {
    const url = new URL(value.originalUrl);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.hash ||
      value.originalUrl.length > 16384
    )
      throw new Error("Invalid original URL");
  }
  if (
    value.rawTarget !== undefined &&
    (typeof value.rawTarget !== "string" ||
      value.rawTarget.length > 16384 ||
      !value.rawTarget.startsWith("/") ||
      /[\r\n]/.test(value.rawTarget))
  )
    throw new Error("Invalid original request target");
}
/** Sign at the trusted transport before forwarding to a Fetch-only cloud function. */
export async function signIngress(
  request: Request,
  metadata: Metadata,
  secret: string,
  at = Date.now(),
) {
  validate(metadata);
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", await key(secret), message(request, metadata, at)),
  );
  return JSON.stringify({
    metadata,
    at,
    signature: Array.from(signature, (b) => b.toString(16).padStart(2, "0")).join(""),
  });
}
export async function verifyIngress(
  request: Request,
  secret: string,
  now = Date.now(),
): Promise<Metadata> {
  const header = request.headers.get("x-edgeshield-ingress");
  if (!header || header.length > 2048) throw new Error("Signed ingress metadata is required");
  const packet = JSON.parse(header);
  if (
    !packet ||
    Object.keys(packet).some((k) => !["metadata", "at", "signature"].includes(k)) ||
    !Number.isSafeInteger(packet.at) ||
    Math.abs(now - packet.at) > 30000 ||
    typeof packet.signature !== "string" ||
    !/^[a-f\d]{64}$/.test(packet.signature)
  )
    throw new Error("Invalid ingress metadata");
  validate(packet.metadata);
  const signature = Uint8Array.from(packet.signature.match(/../g) as string[], (p) =>
    Number.parseInt(p, 16),
  );
  if (
    !(await crypto.subtle.verify(
      "HMAC",
      await key(secret),
      signature,
      message(request, packet.metadata, packet.at),
    ))
  )
    throw new Error("Ingress signature mismatch");
  return packet.metadata;
}
