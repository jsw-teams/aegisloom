import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createControlHandler } from "../packages/control-plane/handler.js";
import { SqliteAuthority } from "../packages/control-plane/sqlite.js";
import { HttpDecisionStore } from "../packages/decision-cache/http.js";
import { createNodeServer } from "../packages/runtime/node.js";
import { decision } from "./decision-fixture.js";
import { attackRule, fixture, request } from "./helpers.js";

test("durable authority survives restart, rejects stale writes and audits policy rollback", async () => {
  const dir = await mkdtemp(join(tmpdir(), "shield-test-"));
  const path = join(dir, "state.db");
  let store = new SqliteAuthority(path);
  try {
    await store.put(decision(), 0);
    store.close();
    store = new SqliteAuthority(path);
    assert.equal((await store.get("t", "a".repeat(64), 150))?.id, "d-1");
    await store.revoke("t", "d-1", 151);
    assert.equal(await store.put(decision({ version: 2 }), 0), false);
    const v1 = await store.savePolicy("t", { version: "1", rules: [attackRule] });
    const v2 = await store.savePolicy("t", { version: "1", rules: [] });
    store.activatePolicy("t", v1);
    store.activatePolicy("t", v2);
    store.activatePolicy("t", v1);
    assert.equal(store.activePolicy("t")?.hash, v1);
    assert.throws(() => store.activatePolicy("other", v1));
    assert.ok(store.auditLog("t").some((e) => e.action === "decision.revoke"));
  } finally {
    store.close();
    await rm(dir, { recursive: true });
  }
});
test("HTTP decision client and control API enforce tenant roles without forwarding identity", async () => {
  const store = new SqliteAuthority(":memory:");
  const adminToken = "a".repeat(40),
    runtimeToken = "b".repeat(40);
  try {
    const handler = await createControlHandler(
      store,
      [
        { token: adminToken, tenant: "t", role: "admin" },
        { token: runtimeToken, tenant: "t", role: "runtime" },
      ],
      store,
    );
    const transport = (url: RequestInfo | URL, init?: RequestInit) =>
      handler(new Request(url, init));
    const runtime = new HttpDecisionStore("https://control.test", runtimeToken, "t", transport);
    const admin = new HttpDecisionStore("https://control.test", adminToken, "t", transport);
    const now = Date.now();
    const d = decision({ firstSeen: now, lastSeen: now, expiresAt: now + 10000 });
    assert.equal(await runtime.put(d, 0), true);
    assert.equal((await runtime.get("t", d.key, now))?.id, "d-1");
    await assert.rejects(runtime.revoke("t", "d-1", now));
    await assert.rejects(runtime.generation("other"));
    assert.equal(await admin.revoke("t", "d-1", now), 1);
    assert.equal(await runtime.get("t", d.key, now), undefined);
    assert.equal((await handler(new Request("https://control.test/v1/generation"))).status, 401);
    assert.equal(await runtime.put({ ...d, tenant: "other" }, 0).catch(() => false), false);
  } finally {
    store.close();
  }
});

test("two runtime instances share and revoke decisions through a real loopback HTTP authority", async () => {
  const authority = new SqliteAuthority(":memory:");
  const runtimeToken = "runtime-network-test-token-32-characters";
  const adminToken = "admin-network-test-token-32-characters";
  const handler = await createControlHandler(
    authority,
    [
      { token: runtimeToken, tenant: "t", role: "runtime" },
      { token: adminToken, tenant: "t", role: "admin" },
    ],
    authority,
  );
  const server: Server = createNodeServer(handler, () => {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    return `127.0.0.1:${address.port}`;
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const endpoint = `http://127.0.0.1:${address.port}`;
    const a = await fixture({
      tenant: "t",
      decisions: new HttpDecisionStore(endpoint, runtimeToken, "t", fetch, true),
    });
    const b = await fixture({
      tenant: "t",
      decisions: new HttpDecisionStore(endpoint, runtimeToken, "t", fetch, true),
    });
    const ctx = { tenant: "t", verifiedClientIp: "192.0.2.1" };
    await a.handle(request("?q=attack"), ctx);
    assert.equal(a.events.at(-1)?.source, "rule");
    await a.handle(request("?q=attack"), ctx);
    assert.equal(a.events.at(-1)?.source, "l1");
    await b.handle(request("?q=attack"), ctx);
    assert.equal(b.events.at(-1)?.source, "l2");
    const id = a.events.at(-1)?.decisionId;
    assert.ok(id);
    const admin = new HttpDecisionStore(endpoint, adminToken, "t", fetch, true);
    await admin.revoke("t", id, Date.now());
    await a.handle(request("?q=attack"), ctx);
    assert.equal(a.events.at(-1)?.source, "rule");
    assert.equal(a.forwarded.length + b.forwarded.length, 0);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    authority.close();
  }
});
