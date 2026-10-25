import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  importSource,
  type SourceConfig,
  validateSources,
} from "../integrations/rule-converter/sources.js";
import { readRunConfig } from "../packages/cli/config.js";
import { importConfiguredSource } from "../packages/cli/sources.js";
import { digest } from "../packages/core/types.js";
import { attackRule } from "./helpers.js";

test("shipped demonstration sources retain valid byte-level pins after formatting", async () => {
  const { readSources } = await import("../packages/cli/sources.js");
  const file = "examples/demo/sources.yaml";
  const sources = await readSources(file);
  for (const source of sources.ruleSources) {
    const original = await readFile(`examples/demo/${source.location}`);
    assert.equal(await digest(original), source.sha256);
  }
  assert.equal((await importConfiguredSource(file, "local-ir")).rules.length, 1);
});

const bytes = new TextEncoder().encode(JSON.stringify({ version: "1", rules: [attackRule] }));
async function config(): Promise<SourceConfig> {
  return {
    version: "1",
    permittedLicenses: ["Apache-2.0"],
    upstreams: [
      {
        id: "cloud",
        kind: "cloud",
        origin: "https://origin.example",
        originTokenEnv: "CLOUD_TOKEN",
        timeoutMs: 10000,
        maxResponseBytes: 1000000,
      },
      {
        id: "vps",
        kind: "vps",
        origin: "https://vps.example",
        originTokenEnv: "VPS_TOKEN",
        timeoutMs: 10000,
        maxResponseBytes: 1000000,
      },
    ],
    ruleSources: [
      {
        id: "local",
        enabled: true,
        location: "policy.json",
        format: "shield-ir",
        version: "1.0",
        sha256: await digest(bytes),
        license: "Apache-2.0",
        service: "api",
      },
    ],
  };
}

test("configured cloud and VPS origins are exact HTTPS targets with secret references", async () => {
  const good = await config();
  assert.equal(validateSources(good).upstreams.length, 2);
  for (const origin of [
    "http://vps.example",
    "https://user:pass@vps.example",
    "https://vps.example/path",
    "https://vps.example?target=other",
  ])
    assert.throws(() =>
      validateSources({ ...good, upstreams: [{ ...good.upstreams[0], origin }] }),
    );
  assert.throws(
    () => validateSources({ ...good, upstreams: [...good.upstreams, good.upstreams[0]] }),
    /Duplicate/,
  );
  assert.throws(() => validateSources({ ...good, script: "unsafe" }), /Invalid/);
});

test("source pins, licenses, enabled state and service scope gate actual import", async () => {
  const good = await config();
  const policy = await importSource(good, "local", bytes);
  assert.equal(policy.rules[0]?.provenance?.sha256, await digest(bytes));
  await assert.rejects(importSource(good, "local", new Uint8Array([1])), /checksum/);
  await assert.rejects(
    importSource({ ...good, permittedLicenses: ["MIT"] }, "local", bytes),
    /license/,
  );
  await assert.rejects(
    importSource(
      { ...good, ruleSources: [{ ...good.ruleSources[0]!, enabled: false }] },
      "local",
      bytes,
    ),
    /disabled/,
  );
  await assert.rejects(
    importSource(
      { ...good, ruleSources: [{ ...good.ruleSources[0]!, service: "other" }] },
      "local",
      bytes,
    ),
    /scope/,
  );
  for (const location of [
    "../private",
    "http://rules.example",
    "/etc/passwd",
    "C:\\secrets",
    "https://a:b@rules.example/x",
  ])
    assert.throws(() =>
      validateSources({ ...good, ruleSources: [{ ...good.ruleSources[0], location }] }),
    );
});

test("bounded file and remote downloads validate bytes before policy parsing", async () => {
  const dir = await mkdtemp(join(tmpdir(), "shield-sources-"));
  try {
    const good = await config(),
      file = join(dir, "sources.json");
    await writeFile(file, JSON.stringify(good));
    await writeFile(join(dir, "policy.json"), bytes);
    assert.equal((await importConfiguredSource(file, "local")).rules.length, 1);
    await writeFile(join(dir, "policy.json"), new Uint8Array(131073));
    await assert.rejects(importConfiguredSource(file, "local"), /128KiB/);
    good.ruleSources[0]!.location = "https://rules.example/pinned.yaml";
    await writeFile(file, JSON.stringify(good));
    const remote = async (_url: unknown, options: RequestInit | undefined) => {
      assert.equal(options?.redirect, "error");
      assert.equal(new Headers(options?.headers).get("accept-encoding"), "identity");
      return new Response(bytes);
    };
    assert.equal(
      (await importConfiguredSource(file, "local", undefined, remote as typeof fetch)).rules.length,
      1,
    );
    for (const response of [
      new Response(null, { status: 302, headers: { location: "https://other.example" } }),
      new Response(bytes, { headers: { "content-encoding": "gzip" } }),
      new Response(new Uint8Array(131073)),
    ])
      await assert.rejects(
        importConfiguredSource(file, "local", undefined, (async () => response) as typeof fetch),
      );
    const run = {
      tenant: "test",
      service: "api",
      publicHosts: ["api.example"],
      routes: [],
      policyFile: "policy.json",
      upstream: { file: "sources.json", id: "vps" },
      listen: { host: "127.0.0.1", port: 9000 },
      decisions: { kind: "sqlite", path: "state.db" },
    };
    await writeFile(join(dir, "shield.json"), JSON.stringify(run));
    assert.equal((await readRunConfig(join(dir, "shield.json"))).upstream?.file, file);
    await writeFile(
      join(dir, "shield.json"),
      JSON.stringify({ ...run, origin: "https://unapproved.example" }),
    );
    await assert.rejects(readRunConfig(join(dir, "shield.json")), /Invalid/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
