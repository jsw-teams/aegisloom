import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { readDeployment } from "../../scr/cli/deployment.js";

test("each platform can select a VPS IPv4/IPv6 address or load-balancer CNAME without including business functions", async () => {
  const directory = await mkdtemp(join(tmpdir(), "shield-origins-"));
  try {
    const file = join(directory, "config.yml");
    await writeFile(
      file,
      JSON.stringify({
        platform: "cloudflare",
        tenant: "test",
        service: "api",
        publicHosts: ["api.test"],
        secLangFile: "rules.json",
        secretFile: "secret.yml",
        originDirectory: "origin",
        routes: [{ business: "app", path: "/api", methods: ["GET"], authenticated: false }],
        listen: { host: "127.0.0.1", port: 0 },
      }),
    );
    for (const platform of ["cloudflare", "vercel", "netlify", "esa", "edgeone"] as const) {
      await mkdir(join(directory, "origin", platform, "app"), { recursive: true });
      const path = join(directory, "origin", platform, "app", "config.yml");
      for (const url of [
        "https://192.0.2.10",
        "https://[2001:db8::1]:8443",
        "https://lb.business.example",
      ]) {
        await writeFile(path, JSON.stringify({ mode: "proxy", platform, url }));
        const loaded = await readDeployment(file, platform);
        assert.equal(loaded.config.origins.app!.origin, new URL(url).origin);
        assert.deepEqual(loaded.config.origins.app!.allowedOrigins, [new URL(url).origin]);
        assert.equal(loaded.config.platform, platform);
      }
      for (const url of [
        "http://192.0.2.10",
        "https://user:password@origin.test",
        "https://origin.test/path",
        "https://origin.test/?override=yes",
      ]) {
        await writeFile(path, JSON.stringify({ mode: "proxy", platform, url }));
        await assert.rejects(readDeployment(file, platform), /exact HTTPS/);
      }
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("one platform loads distinct named VPS and CNAME origins and rejects missing or unsafe business names", async () => {
  const directory = await mkdtemp(join(tmpdir(), "shield-business-config-"));
  try {
    const config = {
      platform: "edgeone",
      tenant: "test",
      service: "api",
      publicHosts: ["api.test"],
      secLangFile: "rules.json",
      secretFile: "secret.yml",
      originDirectory: "origin",
      listen: { host: "127.0.0.1", port: 0 },
      routes: [
        { business: "orders", path: "/orders", methods: ["GET"], authenticated: false },
        { business: "search", path: "/search", methods: ["GET"], authenticated: false },
      ],
    };
    const file = join(directory, "config.yml");
    for (const [name, url] of Object.entries({
      orders: "https://192.0.2.10",
      search: "https://lb.search.example",
    })) {
      await mkdir(join(directory, "origin/edgeone", name), { recursive: true });
      await writeFile(
        join(directory, "origin/edgeone", name, "config.yml"),
        JSON.stringify({ platform: "edgeone", mode: "proxy", url }),
      );
    }
    const save = () => writeFile(file, JSON.stringify(config));
    await save();
    const loaded = await readDeployment(file);
    assert.deepEqual(Object.keys(loaded.businesses), ["orders", "search"]);
    assert.equal(loaded.config.origins.orders!.origin, "https://192.0.2.10");
    assert.equal(loaded.config.origins.search!.origin, "https://lb.search.example");
    assert.match(
      loaded.businesses.orders!.originFile.replaceAll("\\", "/"),
      /origin\/edgeone\/orders\/config.yml$/,
    );
    for (const name of ["../vercel/orders", "/absolute", "", "has/slash"]) {
      config.routes[0]!.business = name;
      await save();
      await assert.rejects(readDeployment(file), /valid business name/);
    }
    config.routes[0]!.business = "missing";
    await save();
    await assert.rejects(readDeployment(file), /ENOENT/);
    config.routes[0]!.business = "orders";
    await save();
    await writeFile(
      join(directory, "origin/edgeone/orders/config.yml"),
      "platform: vercel\nmode: proxy\nurl: https://192.0.2.10\n",
    );
    await assert.rejects(readDeployment(file), /platform or mode mismatch/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
