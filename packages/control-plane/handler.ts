import { digest } from "../core/types.js";
import type { DecisionStore, SecurityDecision } from "../decision-cache/model.js";
import { limitsWith, readBody } from "../http-boundary/index.js";
import type { SqliteAuthority } from "./sqlite.js";

export interface Credential {
  token: string;
  tenant: string;
  role: "runtime" | "admin";
}
function validDecision(value: unknown, tenant: string, now: number): value is SecurityDecision {
  if (!value || typeof value !== "object") return false;
  const d = value as SecurityDecision;
  if (
    Object.keys(d).some(
      (key) =>
        ![
          "id",
          "tenant",
          "key",
          "policy",
          "ruleId",
          "source",
          "confidence",
          "evidenceHash",
          "firstSeen",
          "lastSeen",
          "expiresAt",
          "generation",
          "version",
          "revoked",
          "cloud",
        ].includes(key),
    )
  )
    return false;
  return (
    d.tenant === tenant &&
    /^[a-f0-9]{64}$/.test(d.key) &&
    /^[a-f0-9]{64}$/.test(d.policy) &&
    /^[a-f0-9]{64}$/.test(d.evidenceHash) &&
    /^[a-zA-Z0-9_-]{1,64}$/.test(d.ruleId) &&
    /^[a-zA-Z0-9-]{1,64}$/.test(d.id) &&
    d.source === "rule" &&
    d.confidence >= 0 &&
    d.confidence <= 0.9 &&
    Number.isSafeInteger(d.firstSeen) &&
    d.firstSeen <= now + 5000 &&
    d.firstSeen >= now - 86400000 &&
    d.lastSeen === d.firstSeen &&
    Number.isSafeInteger(d.expiresAt) &&
    d.expiresAt > now &&
    d.expiresAt <= now + 86400000 &&
    Number.isSafeInteger(d.generation) &&
    d.generation >= 0 &&
    d.version === 1 &&
    d.revoked === false &&
    ["pending", "unsupported"].includes(d.cloud)
  );
}
export async function createControlHandler(
  store: DecisionStore,
  credentials: Credential[],
  authority?: SqliteAuthority,
) {
  const keys = new Map<string, Omit<Credential, "token">>();
  for (const c of credentials) {
    if (c.token.length < 32 || !/^[a-zA-Z0-9_-]{1,64}$/.test(c.tenant))
      throw new Error("Invalid control credential");
    const hash = await digest(c.token);
    if (keys.has(hash)) throw new Error("Duplicate control credential");
    keys.set(hash, { tenant: c.tenant, role: c.role });
  }
  if (!keys.size) throw new Error("Control API requires credentials");
  return async (request: Request): Promise<Response> => {
    const reply = (body: unknown, status = 200) =>
      Response.json(body, { status, headers: { "cache-control": "no-store" } });
    const auth = request.headers.get("authorization");
    if (!auth?.startsWith("Bearer ") || auth.length > 2048)
      return reply({ error: "unauthorized" }, 401);
    const credential = keys.get(await digest(auth.slice(7)));
    if (!credential) return reply({ error: "unauthorized" }, 401);
    const { tenant, role } = credential;
    const url = new URL(request.url);
    const now = Date.now();
    try {
      if (url.pathname === "/v1/generation" && request.method === "GET")
        return reply({ generation: await store.generation(tenant) });
      if (url.pathname === "/v1/decisions" && request.method === "GET") {
        const key = url.searchParams.get("key");
        if (key) {
          if (!/^[a-f0-9]{64}$/.test(key)) return reply({ error: "invalid-key" }, 400);
          return reply({ decision: (await store.get(tenant, key, now)) ?? null });
        }
        if (role !== "admin") return reply({ error: "forbidden" }, 403);
        return reply({ decisions: await store.list(tenant, now) });
      }
      if (url.pathname === "/v1/decisions" && request.method === "PUT") {
        const body = JSON.parse(
          new TextDecoder().decode(await readBody(request, limitsWith({ maxBodyBytes: 16384 }))),
        );
        if (
          !validDecision(body.decision, tenant, now) ||
          !Number.isSafeInteger(body.expectedGeneration)
        )
          return reply({ error: "invalid-decision" }, 400);
        return reply({ applied: await store.put(body.decision, body.expectedGeneration) });
      }
      if (url.pathname === "/v1/revoke" && request.method === "POST") {
        if (role !== "admin") return reply({ error: "forbidden" }, 403);
        const body = JSON.parse(
          new TextDecoder().decode(await readBody(request, limitsWith({ maxBodyBytes: 1024 }))),
        );
        if (typeof body.id !== "string" || !/^[a-zA-Z0-9-]{1,64}$/.test(body.id))
          return reply({ error: "invalid-id" }, 400);
        return reply({ generation: await store.revoke(tenant, body.id, now) });
      }
      if (role !== "admin") return reply({ error: "forbidden" }, 403);
      if (!authority) return reply({ error: "unsupported-authority-operation" }, 501);
      if (url.pathname === "/v1/audit" && request.method === "GET")
        return reply({
          audit: authority.auditLog(tenant, Number(url.searchParams.get("after") ?? 0)),
        });
      if (url.pathname === "/v1/policy" && request.method === "GET")
        return reply(authority.activePolicy(tenant) ?? { error: "no-active-policy" });
      if (url.pathname === "/v1/policy" && request.method === "POST") {
        const policy = JSON.parse(
          new TextDecoder().decode(await readBody(request, limitsWith({ maxBodyBytes: 131072 }))),
        );
        return reply({ hash: await authority.savePolicy(tenant, policy) }, 201);
      }
      if (url.pathname === "/v1/policy/activate" && request.method === "POST") {
        const body = JSON.parse(
          new TextDecoder().decode(await readBody(request, limitsWith({ maxBodyBytes: 1024 }))),
        );
        if (typeof body.hash !== "string" || !/^[a-f0-9]{64}$/.test(body.hash))
          return reply({ error: "invalid-hash" }, 400);
        authority.activatePolicy(tenant, body.hash);
        return reply({ active: body.hash });
      }
      return reply({ error: "not-found" }, 404);
    } catch {
      return reply({ error: "control-operation-rejected" }, 400);
    }
  };
}
