export type PlatformName = "cloudflare" | "vercel" | "netlify" | "esa" | "edgeone";
export type OriginSettings =
  | { mode: "function"; platform: PlatformName; secretsFile?: string; upstreams?: string[] }
  | { mode: "proxy"; platform: PlatformName; url: string }
  | {
      mode: "relay";
      platform: PlatformName;
      endpoint: string;
      publicKeyFile: string;
      authenticationKeyFile: string;
    };
export interface BusinessFunction {
  fetch(
    request: Request,
    env?: Record<string, unknown>,
    context?: BusinessContext,
  ): Promise<Response> | Response;
}
export interface BusinessContext {
  secrets: Record<string, unknown>;
  upstreams: Record<string, { url: string; key: string; binding?: string }>;
  originKeys: Record<string, string>;
}
