import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { readDeployment } from "../../scr/cli/deployment.js";
import { originCredential, validateCredentials } from "../../scr/config.js";

async function fixture(
  run: (directory: string, save: (value: unknown) => Promise<void>) => Promise<void>,
) {
  const directory = await mkdtemp(join(tmpdir(), "edgeaegis-origins-"));
  try {
    await mkdir(join(directory, "rules"));
    await mkdir(join(directory, "origin"));
    await writeFile(join(directory, "rules/config.yml"), "source: source.conf\n");
    await writeFile(
      join(directory, "config.yml"),
      JSON.stringify({
        platform: "cloudflare",
        tenant: "test",
        service: "api",
        secretFile: "secret/credentials.yml",
        listen: { host: "127.0.0.1", port: 0 },
      }),
    );
    await run(directory, (value) =>
      writeFile(join(directory, "origin/config.yml"), JSON.stringify(value)),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("one route file supports VPS IPv4/IPv6, CNAME and external functions on every platform", async () => {
  await fixture(async (directory, save) => {
    for (const platform of ["cloudflare", "vercel", "netlify", "esa", "edgeone"] as const) {
      for (const address of [
        "https://192.0.2.10",
        "https://[2001:db8::1]:8443",
        "https://lb.example",
        "https://external-function.example",
      ]) {
        await save({ routes: [{ pattern: "api.test/api/*", origin: address, key: "orders" }] });
        const { config, businesses } = await readDeployment(
          join(directory, "config.yml"),
          platform,
        );
        assert.equal(config.origins.origin0!.origin, new URL(address).origin);
        assert.equal(config.origins.origin0!.key, "orders");
        assert.equal(config.routes[0]!.prefix, true);
        assert.equal(config.routes[0]!.host, "api.test");
        assert.equal(config.routes[0]!.path, "/api/");
        assert.equal(businesses.origin0!.businessFile, "");
      }
      for (const origin of [
        "http://192.0.2.10",
        "https://user:password@origin.test",
        "https://origin.test/path",
        "https://origin.test/?q=1",
      ]) {
        await save({ routes: [{ pattern: "api.test/*", origin, key: "orders" }] });
        await assert.rejects(readDeployment(join(directory, "config.yml"), platform), /HTTPS/);
      }
    }
  });
});

test("multiple configured functions share the engine and only select their platform and scoped upstreams", async () => {
  await fixture(async (directory, save) => {
    await mkdir(join(directory, "secret"));
    await writeFile(join(directory, "secret/orders.yml"), "setting: private\n");
    for (const name of ["orders", "search"]) {
      await mkdir(join(directory, "origin/cloudflare", name), { recursive: true });
      await writeFile(
        join(directory, "origin/cloudflare", name, "index.js"),
        "export default {fetch(){return new Response('ok')}}",
      );
    }
    const config = {
      upstreams: { us: { url: "https://us.example", key: "us" } },
      routes: [
        {
          pattern: "api.test/orders/*",
          origin: "function:orders",
          secrets: "secret/orders.yml",
          upstreams: ["us"],
        },
        { pattern: "api.test/search", origin: "function:search" },
        { pattern: "second.test/search", origin: "function:search" },
      ],
    };
    await save(config);
    const loaded = await readDeployment(join(directory, "config.yml"));
    assert.deepEqual(Object.keys(loaded.businesses), ["orders", "search"]);
    assert.deepEqual(loaded.config.publicHosts, ["api.test", "second.test"]);
    assert.match(
      loaded.businesses.orders!.businessFile.replaceAll("\\", "/"),
      /origin\/cloudflare\/orders\/index.js$/,
    );
    for (const origin of [
      "function:../vercel/orders",
      "function:/absolute",
      "function:",
      "function:has/slash",
    ]) {
      await save({ routes: [{ pattern: "api.test/*", origin, key: "orders" }] });
      await assert.rejects(readDeployment(join(directory, "config.yml")), /business name/);
    }
    await save({
      routes: [{ pattern: "api.test/*", origin: "function:orders", secrets: "config.yml" }],
    });
    await assert.rejects(readDeployment(join(directory, "config.yml")), /inside secret/);
    await save({
      routes: [{ pattern: "api.test/*", origin: "function:orders", upstreams: ["missing"] }],
    });
    await assert.rejects(readDeployment(join(directory, "config.yml")), /upstream names/);
    for (const pattern of ["*.test/*", "api.test/a*b", "api.test/a/../b", "api.test"]) {
      await save({ routes: [{ pattern, origin: "https://origin.example", key: "app" }] });
      await assert.rejects(readDeployment(join(directory, "config.yml")));
    }
  });
});

test("origin keys are explicit and independent; no legacy shared token fallback exists", () => {
  const credentials = validateCredentials({
    originKeys: { orders: "orders-secret-".repeat(4), search: "search-secret-".repeat(4) },
  });
  assert.equal(originCredential(credentials, "orders"), "orders-secret-".repeat(4));
  assert.throws(() => originCredential(credentials, "missing"), /Missing private origin key/);
  assert.throws(() => originCredential(credentials, "toString"), /Missing private origin key/);
  assert.throws(
    () => validateCredentials({ originToken: "legacy-shared-secret-".repeat(3) }),
    /credentials/,
  );
  assert.throws(
    () =>
      validateCredentials({
        originKeys: { one: "shared-secret-".repeat(4), two: "shared-secret-".repeat(4) },
      }),
    /credentials/,
  );
  assert.throws(
    () =>
      validateCredentials({
        originKeys: { one: "secret-".repeat(8) },
        clientToken: "secret-".repeat(8),
      }),
    /credentials/,
  );
});
