import { createShield, type SecurityEvent, type ShieldOptions } from "../../scr/runtime/index.js";
export const context = {
  tenant: "tenant-a",
  verifiedClientIp: "192.0.2.1",
  httpProtocol: "HTTP/1.1",
};
export const token = "test-only-origin-secret-32-characters-long";
export async function fixture(overrides: Partial<ShieldOptions> = {}) {
  const events: SecurityEvent[] = [];
  const forwarded: { url: string; init: RequestInit | undefined }[] = [];
  const shield = await createShield({
    tenant: "tenant-a",
    service: "api",
    publicHosts: ["api.test"],
    routes: [
      {
        business: "app",
        path: "/api",
        methods: ["GET", "POST"],
        authenticated: false,
        body: "json",
      },
      { business: "app", path: "/private", methods: ["GET"], authenticated: true },
    ],
    secLang: 'SecRule ARGS:q "@contains attack" "id:100,deny"',
    origins: {
      app: {
        origin: "https://origin.test",
        allowedOrigins: ["https://origin.test"],
        originToken: token,
        fetch: async (url, init) => {
          forwarded.push({ url: String(url), init });
          return Response.json({ ok: true });
        },
      },
    },
    event: (e) => events.push(e),
    ...overrides,
  });
  return { ...shield, events, forwarded };
}
export const request = (suffix = "", init?: RequestInit) =>
  new Request(`https://api.test/api${suffix}`, init);
