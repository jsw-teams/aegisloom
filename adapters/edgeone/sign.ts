import { digest } from "../../packages/core/types.js";

async function hmac(key: Uint8Array, value: string): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(
    await crypto.subtle.sign("HMAC", imported, new TextEncoder().encode(value)),
  );
}
/** Tencent API v3 POST JSON profile; differential-tested against the official SDK signer. */
export async function signTc3(input: {
  host: string;
  service: string;
  body: string;
  timestamp: number;
  secretId: string;
  secretKey: string;
}): Promise<string> {
  if (
    !/^[a-z0-9.-]+$/.test(input.host) ||
    !/^[a-z0-9]+$/.test(input.service) ||
    !Number.isSafeInteger(input.timestamp) ||
    input.timestamp < 0
  )
    throw new Error("Invalid TC3 signing scope");
  const date = new Date(input.timestamp * 1000).toISOString().slice(0, 10);
  const signedHeaders = "content-type;host";
  const canonical = `POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:${input.host}\n\n${signedHeaders}\n${await digest(input.body)}`;
  const scope = `${date}/${input.service}/tc3_request`;
  const toSign = `TC3-HMAC-SHA256\n${input.timestamp}\n${scope}\n${await digest(canonical)}`;
  const dateKey = await hmac(new TextEncoder().encode(`TC3${input.secretKey}`), date);
  const serviceKey = await hmac(dateKey, input.service);
  const signingKey = await hmac(serviceKey, "tc3_request");
  const signature = Array.from(await hmac(signingKey, toSign), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
  return `TC3-HMAC-SHA256 Credential=${input.secretId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}
