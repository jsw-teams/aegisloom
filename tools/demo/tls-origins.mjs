import { appendFile, readFile } from "node:fs/promises";
import { createServer } from "node:https";
import { resolve } from "node:path";
import { parse } from "../../node_modules/yaml/dist/index.js";

const root = resolve(import.meta.dirname, "../..");
const keys = parse(await readFile(resolve(root, "secret/credentials.yml"), "utf8")).originKeys;
const options = {
  key: await readFile(resolve(root, "tools/lab/key.pem")),
  cert: await readFile(resolve(root, "tools/lab/cert.pem")),
};
const servers = [];
for (const [name, port] of [
  ["vps", 9443],
  ["balance", 9444],
  ["external", 9445],
]) {
  const server = createServer(options, async (request, response) => {
    if (request.headers["x-shield-origin-auth"] !== keys[name]) {
      response.writeHead(403);
      response.end("Origin authentication required");
      return;
    }
    await appendFile(
      resolve(root, "tools/origin-requests.log"),
      `${name} ${request.method} ${request.url}\n`,
    );
    response.writeHead(200, { "content-type": "application/json" });
    response.end(`${JSON.stringify({ business: name, originAuthenticated: true })}\n`);
  });
  await new Promise((done) => server.listen(port, "127.0.0.1", done));
  servers.push(server);
}
console.log("Three authenticated HTTPS origins listening on VM loopback.");
for (const signal of ["SIGINT", "SIGTERM"])
  process.once(signal, () => {
    for (const server of servers) server.close();
  });
