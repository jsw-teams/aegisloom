import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

test("actual CLI listener accepts the configured public Host independently of its loopback socket", {
  timeout: 20000,
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "shield-cli-host-"));
  await mkdir(join(directory, "origin/cloudflare/app"), { recursive: true });
  await mkdir(join(directory, "rules"));
  await writeFile(join(directory, "rules/config.yml"), "source: ../rules.conf\n");
  await writeFile(
    join(directory, "origin/config.yml"),
    JSON.stringify({
      routes: [
        { pattern: "api.vm.test/health", origin: "function:app" },
        { pattern: "second.vm.test/health", origin: "function:app" },
      ],
    }),
  );
  await writeFile(
    join(directory, "origin/cloudflare/app/index.js"),
    'export default {fetch(){return new Response("ok")}}',
  );
  await writeFile(join(directory, "package.json"), '{"type":"module"}');
  await writeFile(join(directory, "rules.conf"), 'SecAction "id:100,phase:1,pass"');
  await writeFile(
    join(directory, "secret.json"),
    JSON.stringify({ originKeys: { app: "test-only-independent-origin-token-32-chars" } }),
  );
  await writeFile(
    join(directory, "shield.json"),
    JSON.stringify({
      tenant: "test",
      service: "api",
      platform: "cloudflare",
      secretFile: "secret.json",
      listen: { host: "127.0.0.1", port: 0 },
    }),
  );
  const child = spawn(
    process.execPath,
    [
      "--import",
      new URL("../node_modules/tsx/dist/loader.mjs", import.meta.url).href,
      resolve("scr/cli/main.ts"),
      "serve",
      join(directory, "shield.json"),
    ],
    {
      cwd: process.cwd(),
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
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
    assert.equal(await status("second.vm.test"), 404);
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
