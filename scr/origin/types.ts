export type PlatformName = "cloudflare" | "vercel" | "netlify" | "esa" | "edgeone";
export type OriginSettings =
  | { mode: "function"; platform: PlatformName }
  | { mode: "proxy"; platform: PlatformName; url: string }
  | {
      mode: "relay";
      platform: PlatformName;
      endpoint: string;
      publicKeyFile: string;
      authenticationKeyFile: string;
    };
export interface BusinessFunction {
  fetch(request: Request): Promise<Response> | Response;
}
