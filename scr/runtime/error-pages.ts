/** Trusted, build-generated HTML only. Never interpolate request data into these pages. */
export interface ErrorPage {
  html: string;
  contentSecurityPolicy: string;
  json?: unknown;
}
export type ErrorPages = Partial<Record<number, ErrorPage>>;

export function wantsHtml(request: Request): boolean {
  const accept = request.headers.get("accept") ?? "";
  if (accept.length > 8192) return false;
  let html = 0;
  let json = 0;
  for (const item of accept.split(",").slice(0, 64)) {
    const [type, ...parameters] = item.trim().toLowerCase().split(";");
    const parameter = parameters.find((p) => p.trim().startsWith("q="));
    const quality = parameter ? Number(parameter.trim().slice(2)) : 1;
    if (!Number.isFinite(quality) || quality < 0 || quality > 1) continue;
    if (type === "text/html" || type === "application/xhtml+xml") html = Math.max(html, quality);
    if (type === "application/json" || type === "application/*" || type === "*/*")
      json = Math.max(json, quality);
  }
  return html > 0 && html >= json;
}

function validate(page: ErrorPage): ErrorPage {
  if (
    typeof page.html !== "string" ||
    new TextEncoder().encode(page.html).length > 262144 ||
    !/<html\b/i.test(page.html)
  )
    throw new Error("Error pages require trusted complete HTML within 256 KiB");
  if (
    typeof page.contentSecurityPolicy !== "string" ||
    !page.contentSecurityPolicy.trim() ||
    page.contentSecurityPolicy.length > 8192 ||
    /[\r\n\0]/.test(page.contentSecurityPolicy)
  )
    throw new Error("Error pages require a bounded, explicit CSP");
  return { ...page };
}

export function createErrorPageResponse(
  request: Request,
  status: number,
  input: ErrorPage,
): Response {
  if (!Number.isInteger(status) || status < 400 || status > 599)
    throw new Error("Unsupported error page status");
  const page = validate(input);
  return new Response(request.method === "HEAD" ? null : page.html, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": page.contentSecurityPolicy,
      "x-content-type-options": "nosniff",
      "x-robots-tag": "noindex, nofollow",
      "referrer-policy": "no-referrer",
      vary: "Accept",
    },
  });
}

export function createErrorPages(input: ErrorPages) {
  if (
    Object.keys(input).some((key) => !/^\d{3}$/.test(key) || Number(key) < 400 || Number(key) > 599)
  )
    throw new Error("Unsupported error page status");
  const pages: ErrorPages = {};
  for (const status of Object.keys(input).map(Number))
    if (input[status]) pages[status] = validate(input[status]);
  return (request: Request, status: number): Response | undefined => {
    const page = pages[status];
    if (page && wantsHtml(request)) return createErrorPageResponse(request, status, page);
    if (page && page.json !== undefined)
      return new Response(request.method === "HEAD" ? null : JSON.stringify(page.json), {
        status,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
          vary: "Accept",
        },
      });
  };
}
