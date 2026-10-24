import { digest, type Fetch, stableJson } from "../../packages/core/types.js";

export interface CommunityConsent {
  upload: boolean;
  subscribe: boolean;
  autoBlock: boolean;
}
export const communityDisabled: Readonly<CommunityConsent> = Object.freeze({
  upload: false,
  subscribe: false,
  autoBlock: false,
});
export interface IpSignal {
  ip: string;
  category: "protocol-abuse" | "injection" | "credential-abuse";
  at: number;
  observations: number;
  confidence: number;
  expiresAt: number;
  reporter: string;
}
export interface Signed<T> {
  value: T;
  signature: string;
}
export interface CommunityFeed {
  version: number;
  issuedAt: number;
  expiresAt: number;
  entries: { ip: string; expiresAt: number; organizations: number }[];
  revoked: string[];
}
const encode = (s: string) => new TextEncoder().encode(s);
function b64(bytes: Uint8Array) {
  let value = "";
  for (const b of bytes) value += String.fromCharCode(b);
  return btoa(value);
}
function unb64(input: string) {
  return Uint8Array.from(atob(input), (c) => c.charCodeAt(0));
}
export async function signValue<T>(value: T, key: CryptoKey): Promise<Signed<T>> {
  return {
    value: structuredClone(value),
    signature: b64(
      new Uint8Array(await crypto.subtle.sign("Ed25519", key, encode(stableJson(value)))),
    ),
  };
}
export async function verifyValue<T>(signed: Signed<T>, key: CryptoKey): Promise<boolean> {
  try {
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      unb64(signed.signature),
      encode(stableJson(signed.value)),
    );
  } catch {
    return false;
  }
}
function ipv4(input: string): number | undefined {
  if (!/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(input)) return undefined;
  const parts = input.split(".").map(Number);
  if (parts.some((n) => n > 255)) return undefined;
  return parts.reduce((n, octet) => ((n << 8) | octet) >>> 0, 0);
}
export function inCidr(ip: string, cidr: string): boolean {
  const [base, bits] = cidr.split("/");
  const a = ipv4(ip),
    b = ipv4(base ?? "");
  const prefix = bits === undefined ? 32 : Number(bits);
  if (a === undefined || b === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 32)
    return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (a & mask) >>> 0 === (b & mask) >>> 0;
}
const reserved = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/3",
];
export function validSignal(s: IpSignal, now: number): boolean {
  return (
    s &&
    Object.keys(s).sort().join(",") ===
      "at,category,confidence,expiresAt,ip,observations,reporter" &&
    ipv4(s.ip) !== undefined &&
    !reserved.some((c) => inCidr(s.ip, c)) &&
    ["protocol-abuse", "injection", "credential-abuse"].includes(s.category) &&
    /^[A-Za-z0-9_-]{1,64}$/.test(s.reporter) &&
    Number.isSafeInteger(s.at) &&
    Math.abs(now - s.at) <= 3600000 &&
    Number.isSafeInteger(s.observations) &&
    s.observations >= 3 &&
    s.observations <= 1000000 &&
    Number.isFinite(s.confidence) &&
    s.confidence >= 0.9 &&
    s.confidence <= 1 &&
    Number.isSafeInteger(s.expiresAt) &&
    s.expiresAt > now &&
    s.expiresAt <= now + 86400000
  );
}
/** Experimental local service logic. Reporter independence is provisioned, never self-declared. */
export class CommunityHub {
  private readonly reports = new Map<string, Map<string, IpSignal>>();
  private readonly revoked = new Set<string>();
  private version = 0;
  private readonly keyOwners = new Map<string, string>();
  constructor(
    private readonly reporters: Map<string, { publicKey: CryptoKey; organization: string }>,
    private readonly warningCidrs: string[],
    private readonly capacity = 10000,
  ) {
    if (
      reporters.size > 1000 ||
      !Number.isInteger(capacity) ||
      capacity < 1 ||
      capacity > 100000 ||
      [...reporters.values()].some((r) => !/^[A-Za-z0-9_-]{1,64}$/.test(r.organization))
    )
      throw new Error("Invalid community reporter registry/capacity");
  }
  async accept(report: Signed<IpSignal>, now = Date.now()): Promise<boolean> {
    if (!report?.value || !validSignal(report.value, now)) return false;
    const reporter = this.reporters.get(report.value.reporter);
    if (
      !reporter ||
      !validSignal(report.value, now) ||
      this.warningCidrs.some((c) => inCidr(report.value.ip, c)) ||
      this.revoked.has(report.value.ip) ||
      !(await verifyValue(report, reporter.publicKey))
    )
      return false;
    let fingerprint: string;
    try {
      fingerprint = await digest(
        new Uint8Array(await crypto.subtle.exportKey("raw", reporter.publicKey)),
      );
    } catch {
      return false;
    }
    const owner = this.keyOwners.get(fingerprint);
    if (owner && owner !== reporter.organization) return false;
    this.keyOwners.set(fingerprint, reporter.organization);
    for (const [ip, sources] of this.reports) {
      for (const [org, signal] of sources) if (signal.expiresAt <= now) sources.delete(org);
      if (!sources.size) this.reports.delete(ip);
    }
    let sources = this.reports.get(report.value.ip);
    if (!sources) {
      if (this.reports.size >= this.capacity) return false;
      sources = new Map();
      this.reports.set(report.value.ip, sources);
    }
    const prior = sources.get(reporter.organization);
    if (prior && prior.at >= report.value.at) return false;
    sources.set(reporter.organization, structuredClone(report.value));
    return true;
  }
  revoke(ip: string): void {
    if (this.revoked.size >= this.capacity)
      throw new Error("Community revocation capacity reached");
    this.reports.delete(ip);
    this.revoked.add(ip);
  }
  async snapshot(privateKey: CryptoKey, now = Date.now()): Promise<Signed<CommunityFeed>> {
    const entries = [...this.reports].flatMap(([ip, sources]) => {
      const fresh = [...sources.values()].filter((s) => s.expiresAt > now);
      return fresh.length >= 3
        ? [
            {
              ip,
              expiresAt: Math.min(...fresh.map((s) => s.expiresAt)),
              organizations: fresh.length,
            },
          ]
        : [];
    });
    return signValue(
      {
        version: ++this.version,
        issuedAt: now,
        expiresAt: now + 300000,
        entries,
        revoked: [...this.revoked],
      },
      privateKey,
    );
  }
}
export class CommunitySubscriber {
  private feed: CommunityFeed | undefined;
  private version: number;
  constructor(
    private readonly consent: CommunityConsent,
    private readonly key: CryptoKey,
    private readonly warningCidrs: string[],
    checkpoint = 0,
  ) {
    if (
      !Number.isSafeInteger(checkpoint) ||
      checkpoint < 0 ||
      [consent.upload, consent.subscribe, consent.autoBlock].some((v) => typeof v !== "boolean")
    )
      throw new Error("Invalid community consent/checkpoint");
    this.consent = { ...consent };
    this.version = checkpoint;
  }
  async ingest(signed: Signed<CommunityFeed>, now = Date.now()): Promise<void> {
    if (!this.consent.subscribe) throw new Error("Community subscription disabled");
    if (!(await verifyValue(signed, this.key)))
      throw new Error("Invalid community snapshot signature");
    const f = signed.value;
    if (
      !Number.isSafeInteger(f.version) ||
      f.version <= this.version ||
      f.issuedAt > now + 5000 ||
      f.issuedAt < now - 300000 ||
      f.expiresAt <= now ||
      f.expiresAt > now + 300000 ||
      !Array.isArray(f.entries) ||
      f.entries.length > 10000 ||
      !Array.isArray(f.revoked) ||
      f.revoked.length > 10000 ||
      f.entries.some(
        (e) =>
          ipv4(e.ip) === undefined ||
          !Number.isSafeInteger(e.expiresAt) ||
          e.expiresAt <= now ||
          e.expiresAt > now + 86400000 ||
          !Number.isSafeInteger(e.organizations) ||
          e.organizations < 3,
      )
    )
      throw new Error("Stale/invalid community feed");
    this.feed = structuredClone(f);
    this.version = f.version;
  }
  shouldBlock(ip: string, now = Date.now()): boolean {
    if (
      !this.consent.subscribe ||
      !this.consent.autoBlock ||
      !this.feed ||
      this.feed.expiresAt <= now ||
      this.feed.revoked.includes(ip) ||
      [...reserved, ...this.warningCidrs].some((c) => inCidr(ip, c))
    )
      return false;
    return this.feed.entries.some((e) => e.ip === ip && e.expiresAt > now);
  }
  checkpoint(): number {
    return this.version;
  }
}
export async function uploadSignal(
  consent: CommunityConsent,
  signal: Signed<IpSignal>,
  endpoint: string,
  allowedOrigins: string[],
  transport: Fetch = fetch,
): Promise<void> {
  if (!consent.upload) throw new Error("Community upload consent is disabled");
  const url = new URL(endpoint);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    !allowedOrigins.includes(url.origin) ||
    !validSignal(signal.value, Date.now())
  )
    throw new Error("Invalid community destination or privacy-safe signal");
  const response = await transport(url, {
    method: "POST",
    redirect: "manual",
    signal: AbortSignal.timeout(5000),
    headers: { "content-type": "application/json" },
    body: JSON.stringify(signal),
  });
  if (!response.ok) throw new Error(`Community upload status ${response.status}`);
}
