import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const directory = await mkdtemp(join(tmpdir(), "shield-smoke-"));
const admin = "smoke-test-admin-token-32-characters-long";
const tsx = new URL("../node_modules/tsx/dist/loader.mjs", import.meta.url).href;
const entry = fileURLToPath(new URL("../examples/local/server.ts", import.meta.url));
const child = spawn(process.execPath, ["--import", tsx, entry], {
  cwd: directory,
  env: { ...process.env, SHIELD_LOCAL_BASE_PORT: "0", SHIELD_ADMIN_TOKEN: admin },
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true,
});
let output = "",
  errors = "";
child.stdout.on("data", (d) => {
  output += d;
});
child.stderr.on("data", (d) => {
  errors += d;
});
let startupTimer;
try {
  await new Promise((resolve, reject) => {
    startupTimer = setTimeout(() => reject(new Error(`Local startup timeout: ${errors}`)), 20000);
    child.stdout.on("data", () => {
      if (
        output
          .split(/\r?\n/)
          .slice(0, -1)
          .some((line) => line.startsWith('{"ready":'))
      )
        resolve();
    });
    child.once("exit", (code) => reject(new Error(`Local startup exit ${code}: ${errors}`)));
  });
  clearTimeout(startupTimer);
  const ready = output
    .split(/\r?\n/)
    .filter((line) => line.startsWith('{"ready":'))
    .map((line) => JSON.parse(line).ready)[0];
  assert.ok(ready);
  for (const endpoint of Object.values(ready))
    assert.equal(new URL(endpoint).hostname, "127.0.0.1");
  const base = ready.edge;
  for (const [path, expected] of [
    ["/api/echo?q=hello", 200],
    ["/api/echo?q=shield-attack-test", 403],
    ["/api/echo?q=shield-attack-test", 403],
    ["/unknown", 404],
  ]) {
    const r = await fetch(base + path);
    assert.equal(r.status, expected);
    await r.arrayBuffer();
  }
  const direct = await fetch(`${ready.origin}/api/echo`);
  assert.equal(direct.status, 403);
  await direct.arrayBuffer();
  const endpoint = ready.control;
  const unauthorized = await fetch(`${endpoint}/v1/generation`);
  assert.equal(unauthorized.status, 401);
  await unauthorized.arrayBuffer();
  const list = await fetch(`${endpoint}/v1/decisions`, {
    headers: { authorization: `Bearer ${admin}` },
  });
  const decisions = (await list.json()).decisions;
  assert.equal(decisions.length, 1);
  const revoke = await fetch(`${endpoint}/v1/revoke`, {
    method: "POST",
    headers: { authorization: `Bearer ${admin}`, "content-type": "application/json" },
    body: JSON.stringify({ id: decisions[0].id }),
  });
  assert.equal(revoke.status, 200);
  await revoke.arrayBuffer();
  const repeated = await fetch(`${base}/api/echo?q=shield-attack-test`);
  assert.equal(repeated.status, 403);
  await repeated.arrayBuffer();
  const events = output
    .split(/\r?\n/)
    .filter((s) => s.startsWith("{"))
    .map((s) => JSON.parse(s));
  const attack = events.filter((e) => ["rule", "l1"].includes(e.source));
  assert.deepEqual(
    attack.map((e) => e.source),
    ["rule", "l1", "rule"],
  );
  console.log(
    "Local process smoke passed: 200 proxy, rule -> L1 -> revoke -> rule, origin isolation, control authentication.",
  );
} finally {
  clearTimeout(startupTimer);
  if (child.exitCode === null) {
    const exited = once(child, "exit");
    child.kill("SIGTERM");
    await exited;
  }
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
