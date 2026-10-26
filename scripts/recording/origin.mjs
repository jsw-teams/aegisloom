// Isolated HTTPS acceptance fixture; no database queries or production data.

import { timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:https";
import { catalog } from "./verify-catalog.mjs";

const inventory = catalog();

let hits = 0;
writeFileSync("origin.pid", String(process.pid));
const server = createServer(
  { key: readFileSync("tls/key.pem"), cert: readFileSync("tls/cert.pem") },
  (request, response) => {
    if (
      request.method === "GET" &&
      new URL(request.url, "https://localhost").pathname === "/rules.yaml"
    ) {
      response.writeHead(200, { "content-type": "application/yaml", "cache-control": "no-store" });
      response.end(readFileSync("rules.yaml"));
      return;
    }
    const expected = Buffer.from(process.env.SHIELD_ORIGIN_TOKEN || ""),
      given = Buffer.from(request.headers["x-shield-origin-auth"] || "");
    if (
      expected.length < 32 ||
      given.length !== expected.length ||
      !timingSafeEqual(given, expected)
    ) {
      response.writeHead(403);
      response.end("Origin authentication required\n");
      return;
    }
    hits++;
    writeFileSync("origin-hits.json", JSON.stringify({ hits }));
    let items;
    try {
      items = inventory.query(
        new URL(request.url, "https://localhost").searchParams.get("id") ?? "1",
      );
    } catch {
      response.writeHead(400);
      response.end("Invalid inventory query");
      return;
    }
    response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    response.end(
      `${JSON.stringify({
        service: "isolated-read-only-acceptance-origin",
        method: request.method,
        items,
        id: new URL(request.url, "https://localhost").searchParams.get("id"),
      })}\n`,
    );
  },
);
server.listen(0, "127.0.0.1", () =>
  writeFileSync("origin-url.txt", `https://127.0.0.1:${server.address().port}`),
);
process.once("SIGTERM", () => {
  server.closeAllConnections();
  server.close();
});
