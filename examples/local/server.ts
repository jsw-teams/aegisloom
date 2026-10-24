import { randomBytes, timingSafeEqual } from "node:crypto";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createControlHandler } from "../../packages/control-plane/handler.js";
import { SqliteAuthority } from "../../packages/control-plane/sqlite.js";
import { loadPolicy } from "../../packages/rule-ir/index.js";
import { createShield } from "../../packages/runtime/index.js";
import { createNodeServer } from "../../packages/runtime/node.js";

const secret = process.env.SHIELD_ORIGIN_TOKEN ?? randomBytes(32).toString("hex");
const adminToken = process.env.SHIELD_ADMIN_TOKEN ?? randomBytes(32).toString("hex");
const runtimeToken = process.env.SHIELD_RUNTIME_TOKEN ?? randomBytes(32).toString("hex");
const store = new SqliteAuthority("shield-local.db");
const basePort = Number(process.env.SHIELD_LOCAL_BASE_PORT ?? 8787);
if (!Number.isInteger(basePort) || basePort < 1024 || basePort > 65532)
  throw new Error("Invalid local base port");
const edgeHost = `127.0.0.1:${basePort}`;
const originHost = `127.0.0.1:${basePort + 1}`;
const controlHost = `127.0.0.1:${basePort + 3}`;
const origin = createNodeServer(async (req) => {
  const given = Buffer.from(req.headers.get("x-shield-origin-auth") ?? "");
  const expected = Buffer.from(secret);
  if (given.length !== expected.length || !timingSafeEqual(given, expected))
    return new Response(null, { status: 403 });
  return Response.json({
    service: "protected-local-api",
    method: req.method,
    path: new URL(req.url).pathname,
  });
}, originHost);
const shield = await createShield({
  tenant: "local",
  service: "api",
  publicHosts: [edgeHost],
  revocationPollMs: 0,
  routes: [
    { path: "/api/echo", methods: ["GET", "POST"], authenticated: false, body: "json" },
    { path: "/api/login", methods: ["POST"], authenticated: false, body: "json" },
  ],
  policy: loadPolicy(await readFile(new URL("../rules.yaml", import.meta.url), "utf8")),
  decisions: store,
  proxy: {
    origin: `http://${originHost}`,
    allowedOrigins: [`http://${originHost}`],
    originToken: secret,
    allowLoopbackHttp: true,
  },
  event: (e) => console.log(JSON.stringify(e)),
});
const edge = createNodeServer(
  (req, incoming) =>
    shield.handle(
      req,
      { tenant: "local", verifiedClientIp: incoming.socket.remoteAddress ?? "127.0.0.1" },
      incoming.url,
    ),
  edgeHost,
);
const control = createNodeServer(
  await createControlHandler(
    store,
    [
      { tenant: "local", token: adminToken, role: "admin" },
      { tenant: "local", token: runtimeToken, role: "runtime" },
    ],
    store,
  ),
  controlHost,
);
const servers = [origin, edge, control];
try {
  for (const [index, server] of servers.entries()) {
    server.listen([basePort + 1, basePort, basePort + 3][index], "127.0.0.1");
    await once(server, "listening");
  }
  console.log(`Shield: http://${edgeHost}/api/echo ; authenticated control: http://${controlHost}`);
  console.log(
    "Control tokens come from SHIELD_ADMIN_TOKEN/SHIELD_RUNTIME_TOKEN; generated fallback tokens are intentionally not printed.",
  );
} catch (error) {
  for (const server of servers) server.close();
  store.close();
  throw error;
}
let stopping = false;
const stop = async () => {
  if (stopping) return;
  stopping = true;
  for (const server of servers) server.closeAllConnections();
  await Promise.all(servers.map((s) => new Promise<void>((resolve) => s.close(() => resolve()))));
  store.close();
};
process.once("SIGINT", () => void stop());
process.once("SIGTERM", () => void stop());
