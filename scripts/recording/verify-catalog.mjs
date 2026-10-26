import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { request } from "node:http";
import { DatabaseSync } from "node:sqlite";
import corpus from "./catalog-corpus.json" with { type: "json" };

// Same deliberately vulnerable read-only SQL query as origin.mjs, with synthetic inventory.
export function catalog() {
  const database = new DatabaseSync(":memory:");
  database.exec(
    "CREATE TABLE items(id INTEGER PRIMARY KEY,name TEXT); INSERT INTO items VALUES(1,'one'),(2,'two'); PRAGMA query_only=ON;",
  );
  return {
    query: (id) => database.prepare(`SELECT id,name FROM items WHERE id=${id}`).all(),
    close: () => database.close(),
  };
}
export async function verifyCatalog(origin, gateway, transport = fetch) {
  const token = process.env.SHIELD_ORIGIN_TOKEN;
  const direct = await transport(`${origin}/api/items?id=${encodeURIComponent("1 OR 1=1")}`, {
    headers: { "x-shield-origin-auth": token },
  });
  assert.equal(direct.status, 200);
  assert.equal(
    (await direct.json()).items.length,
    2,
    "Unprotected fixture must actually expose both rows",
  );
  const count = () => JSON.parse(readFileSync("origin-hits.json", "utf8")).hits;
  const before = count();
  const throughGateway = async (url) =>
    new Promise((done, reject) => {
      const target = new URL(url);
      assert.equal(target.protocol, "http:");
      assert.equal(target.hostname, "127.0.0.1");
      const pending = request(
        target,
        { headers: { host: "api.vm.test" }, timeout: 5000 },
        (response) => {
          let bytes = "";
          response.on("data", (part) => {
            bytes += part;
            if (bytes.length > 65536) pending.destroy(new Error("Response size limit"));
          });
          response.on("error", reject);
          response.on("end", () =>
            done(new Response(bytes, { status: response.statusCode, headers: response.headers })),
          );
        },
      );
      pending.on("timeout", () => pending.destroy(new Error("Gateway timeout")));
      pending.on("error", reject);
      pending.end();
    });
  for (const id of corpus.attacks) {
    const response = await throughGateway(`${gateway}/api/items?id=${encodeURIComponent(id)}`);
    assert.equal(response.status, 403, id);
    await response.body?.cancel();
  }
  assert.equal(count(), before, "Blocked variants must never reach the SQL origin");
  for (const id of corpus.legitimate) {
    const response = await throughGateway(`${gateway}/api/items?id=${id}`);
    assert.equal(response.status, 200, id);
    await response.body?.cancel();
  }
  for (const value of corpus.normalQueryValues) {
    const response = await throughGateway(
      `${gateway}/api/items?id=1&q=${encodeURIComponent(value)}`,
    );
    assert.equal(response.status, 200, value);
    assert.equal((await response.json()).items.length, 1);
  }
  assert.equal(count() - before, corpus.legitimate.length + corpus.normalQueryValues.length);
  return {
    unprotectedRows: 2,
    attacksBlocked: corpus.attacks.length,
    attackOriginHits: 0,
    legitimatePassed: corpus.legitimate.length + corpus.normalQueryValues.length,
  };
}
if (process.argv[1]?.endsWith("verify-catalog.mjs")) {
  const origin = readFileSync("origin-url.txt", "utf8").trim();
  console.log(JSON.stringify(await verifyCatalog(origin, process.env.A)));
}
