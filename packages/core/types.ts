/** Only a platform adapter or verified authentication middleware may supply these values. */
export interface TrustedContext {
  verifiedClientIp?: string;
  identity?: string;
  tenant: string;
  clientClass?: string;
  riskScore?: number;
}

export interface SecurityEvent {
  id: string;
  tenant: string;
  at: number;
  kind: "allow" | "block" | "detect" | "error";
  source:
    | "boundary"
    | "route"
    | "identity"
    | "rule"
    | "l1"
    | "l2"
    | "proxy"
    | "storage"
    | "community";
  policy: string;
  ruleId?: string;
  decisionId?: string;
  reason: string;
  /** No URL, query, headers, IP, identity, or body is included by default. */
}

export class ShieldError extends Error {
  constructor(
    public readonly code: string,
    public readonly status = 400,
  ) {
    super(code);
    this.name = "ShieldError";
  }
}

export type Fetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export function requireInteger(value: number, min: number, max: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`Invalid ${name}: expected integer ${min}..${max}`);
  }
  return value;
}

export async function digest(value: string | Uint8Array): Promise<string> {
  const data = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const hash = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(obj[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
