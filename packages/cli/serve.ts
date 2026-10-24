import { timingSafeEqual } from "node:crypto";
import { once } from "node:events";
import type { Server } from "node:http";
import { type Credential, createControlHandler } from "../control-plane/handler.js";
import { SqliteAuthority } from "../control-plane/sqlite.js";
import { HttpDecisionStore } from "../decision-cache/http.js";
import { loadPolicy } from "../rule-ir/index.js";
import { createShield } from "../runtime/index.js";
import { createNodeServer } from "../runtime/node.js";
import { envSecret, readData, readRunConfig } from "./config.js";

function authorized(header: string | null, secret: string): boolean {
  const provided = Buffer.from(header?.startsWith("Bearer ") ? header.slice(7) : "");
  const expected = Buffer.from(secret);
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}
function shutdown(server: Server, close: () => void) {
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    server.close(() => {
      close();
    });
    server.closeIdleConnections();
    setTimeout(() => {
      server.closeAllConnections();
    }, 5000).unref();
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}
export async function serve(configPath: string): Promise<void> {
  const config = await readRunConfig(configPath);
  const authority =
    config.decisions.kind === "sqlite" ? new SqliteAuthority(config.decisions.path) : undefined;
  const store =
    authority ??
    (config.decisions.kind === "http"
      ? new HttpDecisionStore(
          config.decisions.url,
          envSecret(config.decisions.tokenEnv),
          config.tenant,
        )
      : undefined);
  if (!store) throw new Error("No decision store configured");
  const clientToken = config.clientTokenEnv ? envSecret(config.clientTokenEnv) : undefined;
  const shield = await createShield({
    tenant: config.tenant,
    service: config.service,
    publicHosts: config.publicHosts,
    routes: config.routes,
    policy: loadPolicy(await readData(config.policyFile)),
    decisions: store,
    proxy: {
      origin: config.origin,
      allowedOrigins: config.allowedOrigins,
      originToken: envSecret(config.originTokenEnv),
    },
    event: (event) => process.stdout.write(`${JSON.stringify(event)}\n`),
  });
  const host = `${config.listen.host}:${config.listen.port}`;
  const server = createNodeServer(
    (req, incoming) =>
      shield.handle(
        req,
        {
          tenant: config.tenant,
          verifiedClientIp: incoming.socket.remoteAddress ?? "127.0.0.1",
          ...(clientToken && authorized(req.headers.get("authorization"), clientToken)
            ? { identity: "configured-api-client" }
            : {}),
        },
        incoming.url,
      ),
    host,
  );
  server.listen(config.listen.port, config.listen.host);
  await once(server, "listening");
  shutdown(server, () => authority?.close());
  process.stderr.write(`Cloud API Shield listening at http://${host}; policy ${shield.version}\n`);
}
export async function serveControl(path: string, tenant: string, port: number): Promise<void> {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(tenant) || !Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error("Invalid control listener configuration");
  const store = new SqliteAuthority(path);
  const credentials: Credential[] = [
    { tenant, role: "admin", token: envSecret("SHIELD_ADMIN_TOKEN") },
    { tenant, role: "runtime", token: envSecret("SHIELD_RUNTIME_TOKEN") },
  ];
  const handler = await createControlHandler(store, credentials, store);
  const host = `127.0.0.1:${port}`;
  const server = createNodeServer(handler, host);
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
  shutdown(server, () => store.close());
  process.stderr.write(`Shield control API listening at http://${host}\n`);
}
