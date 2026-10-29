import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { createServer, request as send } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { signIngress } from "../../scr/adapters/ingress.js";
import { readCredentials } from "../../scr/cli/config.js";
import { initProject } from "../../scr/cli/init.js";

test("repository-import Vercel output executes full CRS and never publishes its private bundle as static assets", {
  timeout: 30000,
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "edgeaegis-hosting-"));
  await initProject(directory);
  execFileSync(process.execPath, ["tools/hosting-build.mjs", "vercel", directory], {
    windowsHide: true,
    stdio: "pipe",
  });
  const { default: handler } = await import(
    pathToFileURL(join(directory, ".vercel/output/functions/edgeaegis.func/index.mjs")).href
  );
  const server = createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const credentials = await readCredentials(join(directory, "secret/credentials.yml"));
  const request = async (path: string, signed = true) => {
    const ingress = signed
      ? await signIngress(
          new Request(`https://api.example${path}`),
          { httpProtocol: "HTTP/1.1", verifiedClientIp: "192.0.2.70" },
          credentials.ingressKey!,
        )
      : "";
    return new Promise<{ status: number; body: string }>((done, reject) => {
      const req = send(
        {
          host: "127.0.0.1",
          port: address.port,
          path,
          headers: {
            host: "api.example",
            "user-agent": "Mozilla/5.0",
            "x-edgeshield-ingress": ingress,
          },
        },
        (response) => {
          let body = "";
          response.on("data", (chunk) => {
            body += chunk;
          });
          response.on("end", () => done({ status: response.statusCode!, body }));
        },
      );
      req.on("error", reject);
      req.end();
    });
  };
  try {
    assert.equal((await request("/health")).status, 200);
    assert.equal(
      (await request("/health?q=1%20UNION%20SELECT%20password%20FROM%20users")).status,
      403,
    );
    assert.equal((await request("/health", false)).status, 503);
    assert.deepEqual(await readdir(join(directory, "tools/.build/vercel/deploy/public")), []);
    await assert.rejects(readdir(join(directory, ".vercel/output/static")), /ENOENT/);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
});
