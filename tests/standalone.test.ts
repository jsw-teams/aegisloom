import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, request } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { readRunConfig } from "../packages/cli/config.js";
import { attackRule } from "./helpers.js";

test("standalone installed CLI proxies to a real authenticated origin and persists cached decisions across restart", {
  timeout: 30000,
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "shield-standalone-"));
  const token = "isolated-standalone-origin-token-32-chars";
  let hits = 0;
  const origin = createServer((req, res) => {
    if (req.headers["x-shield-origin-auth"] !== token) {
      res.writeHead(403);
      res.end();
      return;
    }
    hits++;
    assert.equal(req.headers["x-forwarded-for"], undefined);
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"ok":true}');
  }).listen(0, "127.0.0.1");
  await once(origin, "listening");
  const address = origin.address();
  assert(address && typeof address !== "string");
  const target = `http://127.0.0.1:${address.port}`;
  await writeFile(
    join(directory, "rules.json"),
    JSON.stringify({ version: "1", rules: [attackRule] }),
  );
  const config = {
    tenant: "standalone",
    service: "api",
    publicHosts: ["api.local.test"],
    policyFile: "rules.json",
    routes: [{ path: "/api", methods: ["GET"], authenticated: false }],
    origin: target,
    allowedOrigins: [target],
    originTokenEnv: "TEST_STANDALONE_TOKEN",
    allowLoopbackHttp: true,
    listen: { host: "127.0.0.1", port: 0 },
    decisions: { kind: "sqlite", path: "state.db" },
  };
  const file = join(directory, "shield.json");
  await writeFile(file, JSON.stringify(config));
  const run = async () => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", resolve("packages/cli/main.ts"), "serve", file],
      {
        windowsHide: true,
        env: { ...process.env, TEST_STANDALONE_TOKEN: token },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let output = "",
      errors = "";
    child.stdout.on("data", (part) => {
      output += part;
    });
    child.stderr.on("data", (part) => {
      errors += part;
    });
    const port = await new Promise<number>((done, reject) => {
      const timer = setTimeout(() => reject(new Error("Standalone readiness timeout")), 10000);
      child.stderr.on("data", () => {
        const match = /listening at http:\/\/127.0.0.1:(\d+);/.exec(errors);
        if (match) {
          clearTimeout(timer);
          done(Number(match[1]));
        }
      });
      child.once("error", reject);
      child.once("exit", () => {
        clearTimeout(timer);
        reject(new Error("Standalone startup failed"));
      });
    });
    return {
      child,
      port,
      events: () =>
        output
          .split(/\r?\n/)
          .filter((s) => s.startsWith("{"))
          .map((s) => JSON.parse(s)),
    };
  };
  const get = (port: number, path: string) =>
    new Promise<number>((done, reject) => {
      const req = request(
        {
          host: "127.0.0.1",
          port,
          path,
          headers: { host: "api.local.test", "x-forwarded-for": "203.0.113.10" },
        },
        (res) => {
          res.resume();
          res.on("end", () => done(res.statusCode!));
        },
      );
      req.on("error", reject);
      req.end();
    });
  let running: Awaited<ReturnType<typeof run>> | undefined;
  const stop = async () => {
    if (running && running.child.exitCode === null) {
      const exited = once(running.child, "exit");
      running.child.kill("SIGTERM");
      await exited;
    }
    running = undefined;
  };
  try {
    running = await run();
    assert.equal(await get(running.port, "/api?q=hello"), 200);
    assert.equal(hits, 1);
    assert.equal(await get(running.port, "/unknown"), 404);
    assert.equal(await get(running.port, "/api?q=attack"), 403);
    assert.equal(await get(running.port, "/api?q=attack"), 403);
    assert.equal(hits, 1);
    assert.deepEqual(
      running
        .events()
        .filter((e) => ["rule", "l1"].includes(e.source))
        .map((e) => e.source),
      ["rule", "l1"],
    );
    await stop();
    running = await run();
    assert.equal(await get(running.port, "/api?q=attack"), 403);
    assert.equal(hits, 1);
    assert.equal(
      running.events().some((e) => e.source === "l2"),
      true,
    );
    await writeFile(file, JSON.stringify({ ...config, listen: { host: "0.0.0.0", port: 8787 } }));
    assert.equal((await readRunConfig(file)).listen.host, "0.0.0.0");
  } finally {
    await stop();
    await new Promise<void>((done) => origin.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
});
