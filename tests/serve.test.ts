import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

test("actual CLI listener accepts the configured public Host independently of its loopback socket", {
  timeout: 20000,
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "shield-cli-host-"));
  await writeFile(join(directory, "policy.json"), JSON.stringify({ version: "1", rules: [] }));
  await writeFile(
    join(directory, "shield.json"),
    JSON.stringify({
      tenant: "test",
      service: "api",
      publicHosts: ["api.vm.test"],
      routes: [],
      policyFile: "policy.json",
      origin: "https://origin.invalid",
      allowedOrigins: ["https://origin.invalid"],
      originTokenEnv: "TEST_ORIGIN_TOKEN",
      listen: { host: "127.0.0.1", port: 0 },
      decisions: { kind: "sqlite", path: "state.db" },
    }),
  );
  const child = spawn(
    process.execPath,
    ["--import", "tsx", resolve("packages/cli/main.ts"), "serve", join(directory, "shield.json")],
    {
      cwd: process.cwd(),
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, TEST_ORIGIN_TOKEN: "test-only-independent-origin-token-32-chars" },
    },
  );
  let stderr = "";
  child.stdout.resume();
  child.stderr.on("data", (part) => {
    stderr += part;
  });
  try {
    const port = await new Promise<number>((done, reject) => {
      const timer = setTimeout(() => reject(new Error(stderr || "CLI readiness timeout")), 10000);
      const check = () => {
        const match = /listening at http:\/\/127\.0\.0\.1:([0-9]+);/.exec(stderr);
        if (match) {
          clearTimeout(timer);
          done(Number(match[1]));
        }
      };
      child.stderr.on("data", check);
      child.once("error", reject);
      child.once("exit", (code) => {
        clearTimeout(timer);
        reject(new Error(`CLI exited ${code}: ${stderr}`));
      });
    });
    const status = (host: string) =>
      new Promise<number>((done, reject) => {
        const outgoing = request(
          { hostname: "127.0.0.1", port, path: "/unknown", headers: { host } },
          (response) => {
            response.resume();
            response.once("end", () => done(response.statusCode!));
          },
        );
        outgoing.once("error", reject);
        outgoing.end();
      });
    assert.equal(await status("api.vm.test"), 404); // Reached the real runtime's route policy.
    assert.equal(await status("forged.example"), 400); // Rejected before the handler.
  } finally {
    if (child.exitCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGTERM");
      await exited;
    }
    await rm(directory, { recursive: true, force: true });
  }
});
