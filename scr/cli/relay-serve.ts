import { once } from "node:events";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { createRelayServer } from "../origin/relay.js";
import { SqliteReplayStore } from "../origin/replay-node.js";
import { createNodeServer } from "../runtime/node.js";
import { readCredentials, readData } from "./config.js";
import { readBusinessFunction } from "./deployment.js";
export async function serveRelay(path: string) {
  const input = (await readData(path)) as {
    publicHost: string;
    privateKeyFile: string;
    authenticationKeyFile: string;
    credentialsFile: string;
    businessFile: string;
    stateFile: string;
    listen: { host: string; port: number };
    maxBytes?: number;
  };
  const base = dirname(resolve(path));
  if (
    !["127.0.0.1", "::1"].includes(input.listen?.host) ||
    !Number.isInteger(input.listen.port) ||
    input.listen.port < 0 ||
    input.listen.port > 65535 ||
    typeof input.publicHost !== "string"
  )
    throw new Error("Relay server requires an explicit loopback listener behind TLS ingress");
  const stateFile = resolve(base, input.stateFile);
  await mkdir(dirname(stateFile), { recursive: true });
  const store = new SqliteReplayStore(stateFile);
  const credentials = await readCredentials(resolve(base, input.credentialsFile));
  const business = await readBusinessFunction(resolve(base, input.businessFile));
  const handler = await createRelayServer({
    serverPrivateKey: JSON.parse(await readFile(resolve(base, input.privateKeyFile), "utf8")),
    authenticationKey: (await readFile(resolve(base, input.authenticationKeyFile), "utf8")).trim(),
    originToken: credentials.originToken,
    business: (request) => Promise.resolve(business.fetch(request)),
    replay: store,
    ...(input.maxBytes ? { maxBytes: input.maxBytes } : {}),
  });
  const server = createNodeServer(
    async (request) =>
      new URL(request.url).pathname === "/_edgeshield/relay"
        ? handler(request)
        : new Response(null, { status: 404 }),
    input.publicHost,
  );
  server.listen(input.listen.port, input.listen.host);
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing relay listener");
  process.stderr.write(
    `Relay listening at http://${input.listen.host}:${address.port}; HTTPS ingress required\n`,
  );
  const stop = () => {
    server.close(() => store.close());
    server.closeIdleConnections();
    setTimeout(() => server.closeAllConnections(), 5000).unref();
  };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
}
