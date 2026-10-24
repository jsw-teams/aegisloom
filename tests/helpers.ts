import { MemoryDecisionStore } from "../packages/decision-cache/index.js";
import { loadPolicy } from "../packages/rule-ir/index.js";
import { createShield, type SecurityEvent, type ShieldOptions } from "../packages/runtime/index.js";

export const attackRule = {
  id: "query-attack",
  name: "Block exploit marker",
  service: "api",
  priority: 10,
  when: { field: "query", key: "q", op: "contains", value: "attack" },
  then: { action: "block" },
  cache: { enabled: true, ttl: "1m" },
};
export const context = { tenant: "tenant-a", verifiedClientIp: "192.0.2.1" };
export const token = "test-only-origin-secret-32-characters-long";
export async function fixture(overrides: Partial<ShieldOptions> = {}) {
  const events: SecurityEvent[] = [];
  const forwarded: { url: string; init: RequestInit | undefined }[] = [];
  const decisions = new MemoryDecisionStore();
  const shield = await createShield({
    tenant: "tenant-a",
    service: "api",
    publicHosts: ["api.test"],
    routes: [
      { path: "/api", methods: ["GET", "POST"], authenticated: false, body: "json" },
      { path: "/private", methods: ["GET"], authenticated: true },
    ],
    policy: loadPolicy({ version: "1", rules: [attackRule] }),
    decisions,
    revocationPollMs: 0,
    proxy: {
      origin: "https://origin.test",
      allowedOrigins: ["https://origin.test"],
      originToken: token,
      fetch: async (url, init) => {
        forwarded.push({ url: String(url), init });
        return Response.json({ ok: true });
      },
    },
    event: (e) => events.push(e),
    ...overrides,
  });
  return { ...shield, decisions, events, forwarded };
}
export const request = (suffix = "", init?: RequestInit) =>
  new Request(`https://api.test/api${suffix}`, init);
