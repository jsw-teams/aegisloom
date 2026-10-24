export interface ApiAsset {
  path: string;
  method: string;
  authenticated: boolean | "unknown";
  source: "openapi" | "observation";
}
/** No remote $ref resolution or network requests; schema security is descriptive, not auth proof. */
export function discoverOpenApi(input: unknown): ApiAsset[] {
  const doc = input as Record<string, any>;
  if (
    !doc ||
    typeof doc.openapi !== "string" ||
    !doc.openapi.startsWith("3.") ||
    !doc.paths ||
    typeof doc.paths !== "object"
  )
    throw new Error("OpenAPI 3.x paths required");
  const result: ApiAsset[] = [];
  for (const [path, item] of Object.entries(doc.paths)) {
    if (!path.startsWith("/") || path.length > 1024 || !item || typeof item !== "object")
      throw new Error("Invalid OpenAPI path item");
    if ("$ref" in item) throw new Error("OpenAPI path references require offline resolution");
    for (const [method, operation] of Object.entries(item)) {
      if (!["get", "post", "put", "patch", "delete", "head", "options"].includes(method)) continue;
      const security = (operation as any)?.security ?? doc.security;
      result.push({
        path,
        method: method.toUpperCase(),
        authenticated: Array.isArray(security)
          ? security.length > 0 && security.every((s: any) => Object.keys(s).length > 0)
          : "unknown",
        source: "openapi",
      });
      if (result.length > 10000) throw new Error("API asset capacity exceeded");
    }
  }
  return result;
}
export function diffAssets(declared: ApiAsset[], observed: { path: string; method: string }[]) {
  const key = (a: { path: string; method: string }) => `${a.method} ${a.path}`;
  const d = new Set(declared.map(key)),
    o = new Set(observed.map(key));
  return {
    undeclared: [...o].filter((k) => !d.has(k)),
    unobserved: [...d].filter((k) => !o.has(k)),
  };
}
