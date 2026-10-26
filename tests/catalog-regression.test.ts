import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { verifySourcePolicy } from "../packages/control-plane/source-regression.js";
import { MemoryDecisionStore } from "../packages/decision-cache/index.js";
import { loadPolicy } from "../packages/rule-ir/index.js";
import { createShield } from "../packages/runtime/index.js";
import corpus from "../scripts/recording/catalog-corpus.json" with { type: "json" };
import policy from "../scripts/recording/catalog-policy.json" with { type: "json" };

test("catalog contract prevents real SQLite row disclosure across encoded variants without blocking normal search text", async () => {
  const db = new DatabaseSync(":memory:");
  db.exec(
    "CREATE TABLE items(id INTEGER PRIMARY KEY,name TEXT); INSERT INTO items VALUES(1,'one'),(2,'two'); PRAGMA query_only=ON;",
  );
  let hits = 0;
  const query = (id: string) => db.prepare(`SELECT id,name FROM items WHERE id=${id}`).all();
  try {
    assert.equal(query("1 OR 1=1").length, 2);
    const runtime = await createShield({
      tenant: "catalog",
      service: "api",
      publicHosts: ["catalog.test"],
      routes: [{ path: "/api/items", methods: ["GET"], authenticated: false }],
      policy: loadPolicy(policy),
      decisions: new MemoryDecisionStore(),
      proxy: {
        origin: "https://origin.invalid",
        allowedOrigins: ["https://origin.invalid"],
        originToken: "isolated-catalog-origin-token-32-characters",
        fetch: async (request) => {
          hits++;
          return Response.json({
            items: query(new URL(String(request)).searchParams.get("id") ?? "1"),
          });
        },
      },
    });
    for (const id of corpus.attacks) {
      const response = await runtime.handle(
        new Request(`https://catalog.test/api/items?id=${encodeURIComponent(id)}`),
        { tenant: "catalog" },
      );
      assert.equal(response.status, 403, id);
      await response.body?.cancel();
    }
    // Duplicate parameter pollution must not hide an invalid value behind a valid one.
    for (const parameters of ["id=1&id=1%20OR%201=1", "id=1%20OR%201=1&id=1"])
      assert.equal(
        (
          await runtime.handle(new Request(`https://catalog.test/api/items?${parameters}`), {
            tenant: "catalog",
          })
        ).status,
        403,
      );
    assert.equal(hits, 0);
    for (const q of corpus.normalQueryValues) {
      const response = await runtime.handle(
        new Request(`https://catalog.test/api/items?id=1&q=${encodeURIComponent(q)}`),
        { tenant: "catalog" },
      );
      assert.equal(response.status, 200);
      assert.equal((await response.json()).items.length, 1);
    }
    assert.equal(hits, 5);
    const samples = [
      ...corpus.attacks.map((id) => ({
        name: id,
        kind: "attack",
        url: `https://simulation.test/api/items?id=${encodeURIComponent(id)}`,
        expectedStatus: 403,
      })),
      ...corpus.legitimate.map((id) => ({
        name: id,
        kind: "legitimate",
        url: `https://simulation.test/api/items?id=${id}`,
        expectedStatus: 204,
      })),
    ];
    assert.equal(
      await verifySourcePolicy(loadPolicy(policy), samples, { requireRuleCoverage: true }),
      22,
    );
    // A policy regression is caught when its attack condition is changed or removed.
    await assert.rejects(verifySourcePolicy(loadPolicy({ version: "1", rules: [] }), samples));
  } finally {
    db.close();
  }
});
