#!/usr/bin/env node
// Real NGINX/OpenResty-compatible TLS/loopback test with a simulated security engine.
// No production origin, DNS, Cloudflare zone or private credentials are contacted.
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { createServer as createHttpsServer, request as httpsRequest } from "node:https";
import { createServer as createTcpServer } from "node:net";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";

const dir = await mkdtemp(join(tmpdir(), "edgeshield-openresty-"));
const token = "edgeShieldOriginTestToken_32_chars_2026";
let nginx;
let engine;
let origin;
async function unusedPort() {
  const socket = createTcpServer().listen(0, "127.0.0.1");
  await once(socket, "listening");
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return port;
}
function get(port, secure, path = "/", headers = {}) {
  return new Promise((resolve, reject) => {
    const send = secure ? httpsRequest : httpRequest;
    const req = send({
      host: "127.0.0.1", port, path, headers,
      ...(secure ? { rejectUnauthorized: false, servername: "localhost" } : {}),
    }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    req.once("error", reject);
    req.end();
  });
}
try {
  for (const prefix of ["origin", "edge"]) {
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", join(dir, prefix + ".key"),
      "-out", join(dir, prefix + ".crt"),
      "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1",
    ], { stdio: "ignore" });
  }
  origin = createHttpsServer({
    cert: await readFile(join(dir, "origin.crt")),
    key: await readFile(join(dir, "origin.key")),
  }, (req, res) => {
    if (req.headers["x-shield-origin-auth"] !== token) {
      res.writeHead(403); res.end("unauthorized origin"); return;
    }
    if (req.headers.host !== "localhost") {
      res.writeHead(400); res.end("bad origin host"); return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      path: req.url, authenticated: true, spoofed: Boolean(req.headers["x-forwarded-for"]),
    }));
  });
  origin.listen(0);
  await once(origin, "listening");
  const originPort = origin.address().port;
  const [bridge, ingress, enginePort] = await Promise.all([
    unusedPort(), unusedPort(), unusedPort(),
  ]);
  engine = createHttpServer((req, res) => {
    if (req.headers.host !== "localhost" || req.headers["x-shield-origin-auth"]) {
      res.writeHead(400); res.end("unsafe ingress"); return;
    }
    if (req.url === "/blocked") {
      res.writeHead(403); res.end("blocked"); return;
    }
    const upstream = httpRequest({
      host: "127.0.0.1", port: bridge, path: req.url, method: req.method,
      headers: { host: "localhost", "x-shield-origin-auth": token },
    }, (remote) => { res.writeHead(remote.statusCode, remote.headers); remote.pipe(res); });
    upstream.once("error", () => { res.writeHead(502); res.end("origin failure"); });
    req.pipe(upstream);
  });
  engine.listen(enginePort, "127.0.0.1");
  await once(engine, "listening");
  const env = {
    ...process.env,
    EDGESHIELD_NGINX_PID: join(dir, "nginx.pid"),
    EDGESHIELD_NGINX_ERROR_LOG: join(dir, "error.log"),
    EDGESHIELD_BRIDGE_PORT: String(bridge),
    EDGESHIELD_INGRESS_PORT: String(ingress),
    EDGESHIELD_ENGINE_PORT: String(enginePort),
    EDGESHIELD_ORIGIN_TOKEN: token,
    EDGESHIELD_UPSTREAM_HOST: "localhost",
    EDGESHIELD_UPSTREAM_PORT: String(originPort),
    EDGESHIELD_UPSTREAM_CA_FILE: join(dir, "origin.crt"),
    EDGESHIELD_PUBLIC_HOST: "localhost",
    EDGESHIELD_TLS_CERT_FILE: join(dir, "edge.crt"),
    EDGESHIELD_TLS_KEY_FILE: join(dir, "edge.key"),
  };
  const rendered = join(dir, "nginx.conf");
  execFileSync(process.execPath, [new URL("./render.mjs", import.meta.url).pathname, rendered], { env });
  execFileSync("nginx", ["-t", "-c", rendered, "-p", dir + "/"]);
  nginx = spawn("nginx", ["-c", rendered, "-p", dir + "/", "-g", "daemon off;"]);
  let actual;
  for (let i = 0; i < 60; i++) {
    try {
      actual = await get(ingress, true, "/allowed?q=1", {
        host: "localhost", "x-shield-origin-auth": "forged",
        "x-forwarded-for": "1.2.3.4",
      });
      break;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 70));
    }
  }
  assert.equal(actual?.status, 200);
  assert.deepEqual(JSON.parse(actual.body), {
    path: "/allowed?q=1", authenticated: true, spoofed: false,
  });
  assert.equal((await get(ingress, true, "/blocked", { host: "localhost" })).status, 403);
  assert.equal((await get(bridge, false, "/allowed")).status, 403);
  assert.equal((await get(bridge, false, "/allowed", { "x-shield-origin-auth": "bad" })).status, 403);
  console.log("PASS: real NGINX TLS ingress, proxy, rejection and authenticated HTTPS origin");
} finally {
  nginx?.kill("SIGTERM");
  if (nginx) await Promise.race([
    once(nginx, "exit"),
    new Promise((resolve) => setTimeout(resolve, 2500)),
  ]);
  if (engine) await new Promise((resolve) => engine.close(resolve));
  if (origin) await new Promise((resolve) => origin.close(resolve));
  await rm(dir, { recursive: true, force: true });
}
