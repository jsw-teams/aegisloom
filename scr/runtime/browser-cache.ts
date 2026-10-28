import { requireInteger } from "../core/types.js";

export interface BrowserCachePolicy {
  /** Maximum freshness lifetime. The origin must also explicitly permit public caching. */
  maxAgeSeconds: number;
}

export function validateBrowserCache(policy: BrowserCachePolicy | undefined): void {
  if (policy === undefined) return;
  if (
    !policy ||
    typeof policy !== "object" ||
    Object.keys(policy).some((k) => k !== "maxAgeSeconds")
  )
    throw new Error("Invalid browser cache policy");
  requireInteger(policy.maxAgeSeconds, 1, 86400, "browser cache lifetime");
}

/** Client caching reduces future network requests; no server-side rule decision is reused. */
export function applyBrowserCache(
  request: Request,
  response: Response,
  headers: Headers,
  policy?: BrowserCachePolicy,
): void {
  headers.set("cache-control", "no-store");
  if (
    !policy ||
    !["GET", "HEAD"].includes(request.method) ||
    response.status !== 200 ||
    request.headers.has("authorization") ||
    request.headers.has("proxy-authorization") ||
    request.headers.has("cookie") ||
    request.headers.has("upgrade") ||
    response.headers.has("set-cookie") ||
    request.headers.get("pragma")?.toLowerCase().includes("no-cache") ||
    /(?:^|,)\s*(?:(?:no-cache|no-store)(?:\s*=|\s*(?:,|$))|max-age\s*=\s*"?0"?(?:\s|,|$))/i.test(
      request.headers.get("cache-control") ?? "",
    )
  )
    return;
  const directives = (response.headers.get("cache-control") ?? "")
    .toLowerCase()
    .split(",")
    .map((part) => part.trim());
  if (
    !directives.includes("public") ||
    directives.some((part) => /^(?:private|no-store|no-cache)(?:\s*=|$)/.test(part))
  )
    return;
  const ages = directives.filter((part) => /^max-age\s*=/.test(part));
  if (ages.length !== 1 || !/^max-age\s*=\s*\d+$/.test(ages[0]!)) return;
  const originAge = Number(ages[0]!.split("=")[1]);
  if (!Number.isSafeInteger(originAge) || originAge < 1) return;
  const vary = (response.headers.get("vary") ?? "").split(",").map((part) => part.trim());
  if (vary.includes("*")) return;
  // Prevent an anonymous browser entry being reused after a login changes credentials.
  for (const name of ["Cookie", "Authorization"])
    if (!vary.some((part) => part.toLowerCase() === name.toLowerCase())) vary.push(name);
  headers.set("vary", vary.filter(Boolean).join(", "));
  // Private prohibits a shared cache from answering before the SecLang entry point.
  // Preserve Date/Age, validators and Vary; never extend the origin freshness lifetime.
  headers.set(
    "cache-control",
    `private, max-age=${Math.min(policy.maxAgeSeconds, originAge)}, must-revalidate`,
  );
}
