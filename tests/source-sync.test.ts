import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { validateSources } from "../integrations/rule-converter/sources.js";
import {
  SourceSyncStore,
  synchronizeSources,
  verifySourcePolicy,
} from "../packages/control-plane/source-sync.js";
import { loadPolicy } from "../packages/rule-ir/index.js";
import { attackRule } from "./helpers.js";

const policy = { version: "1", rules: [attackRule] };
const samples = [
  {
    name: "attack",
    kind: "attack",
    url: "https://simulation.test/api?q=attack",
    expectedStatus: 403,
  },
  {
    name: "legitimate",
    kind: "legitimate",
    url: "https://simulation.test/api?q=hello",
    expectedStatus: 204,
  },
];
async function fixture(work: (file: string, store: SourceSyncStore, config: any) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), "shield-sync-"));
  const store = new SourceSyncStore(join(dir, "candidates.db"));
  const file = join(dir, "sources.json");
  const config = {
    version: "1",
    upstreams: [],
    permittedLicenses: ["Apache-2.0"],
    ruleSources: [
      {
        id: "public",
        enabled: true,
        location: "policy.json",
        format: "shield-ir",
        version: "main",
        license: "Apache-2.0",
        service: "api",
        regressionFile: "samples.json",
      },
    ],
  };
  try {
    await writeFile(file, JSON.stringify(config));
    await writeFile(join(dir, "policy.json"), JSON.stringify(policy));
    await writeFile(join(dir, "samples.json"), JSON.stringify(samples));
    await work(file, store, config);
  } finally {
    store.close();
    await rm(dir, { recursive: true, force: true });
  }
}

test("scheduled source import validates, regresses, deduplicates and never activates", async () =>
  fixture(async (file, store) => {
    const result = await synchronizeSources(file, store, { now: 100000 });
    assert.equal(result[0]?.result, "verified");
    const candidate = store.candidate("public", result[0]!.hash!)!;
    assert.equal(candidate.tests, 2);
    assert.equal(candidate.policy?.rules.length, 1);
    assert.equal((await synchronizeSources(file, store, { now: 100001 }))[0]?.result, "not-due");
    assert.equal(
      (await synchronizeSources(file, store, { now: 3700000 }))[0]?.hash,
      result[0]?.hash,
    );
    assert.equal(store.audit().length, 2);
    // SQLite archive holds candidate data only; it never writes the runtime's policy file.
    assert.deepEqual(JSON.parse(await readFile(join(file, "..", "policy.json"), "utf8")), policy);
  }));

test("private HTTPS repositories receive scoped bearer credentials; diagnostics never echo them", async () =>
  fixture(async (file, store, config) => {
    config.ruleSources[0].location =
      "https://api.github.com/repos/owner/private/contents/rules.json?ref=main";
    config.ruleSources[0].authTokenEnv = "SHIELD_TEST_PRIVATE_RULE_TOKEN";
    const credential = "test-private-rule-token-never-log";
    process.env.SHIELD_TEST_PRIVATE_RULE_TOKEN = credential;
    await writeFile(file, JSON.stringify(config));
    let calls = 0;
    try {
      const results = await synchronizeSources(file, store, {
        transport: async (_url, init) => {
          calls++;
          assert.equal(new Headers(init?.headers).get("authorization"), `Bearer ${credential}`);
          assert.equal(init?.redirect, "error");
          return new Response(JSON.stringify(policy));
        },
      });
      assert.equal(results[0]?.result, "verified");
      assert.equal(calls, 1);
      assert.equal(
        JSON.stringify([
          results,
          store.audit(),
          store.candidate("public", results[0]!.hash!),
        ]).includes(credential),
        false,
      );
      const failed = await synchronizeSources(file, store, {
        now: Date.now() + 3600001,
        transport: async () => {
          throw new Error(credential);
        },
      });
      assert.equal(failed[0]?.result, "failed");
      assert.equal(JSON.stringify([failed, store.audit()]).includes(credential), false);
    } finally {
      delete process.env.SHIELD_TEST_PRIVATE_RULE_TOKEN;
    }
  }));

test("invalid rule update and false-positive regression leave previous verified candidate intact", async () =>
  fixture(async (file, store) => {
    const good = (await synchronizeSources(file, store, { now: 100000 }))[0]!;
    await writeFile(
      join(file, "..", "samples.json"),
      JSON.stringify([
        { ...samples[0] },
        { ...samples[1], url: "https://simulation.test/api?q=attack" },
      ]),
    );
    const failed = await synchronizeSources(file, store, { now: 3700000 });
    assert.equal(failed[0]?.result, "failed");
    assert.equal(store.candidate("public", good.hash!)?.status, "verified");
  }));

test("unconverted third-party sources remain bytes-only candidates with explicit status", async () =>
  fixture(async (file, store, config) => {
    config.ruleSources[0].format = "seclang";
    delete config.ruleSources[0].regressionFile;
    await writeFile(file, JSON.stringify(config));
    const result = (await synchronizeSources(file, store))[0]!;
    assert.equal(result.result, "needs-conversion");
    assert.equal(store.candidate("public", result.hash!)?.policy, undefined);
  }));

test("bounded archive fails closed and invalid credential/path configuration is rejected", async () =>
  fixture(async (_file, _store, config) => {
    for (const extra of [
      { regressionFile: "../private" },
      { conversionReportFile: "C:\\secret" },
      { authTokenEnv: "TOKEN" },
      { location: "https://rules.example/p?token=private" },
    ])
      assert.throws(() =>
        validateSources({ ...config, ruleSources: [{ ...config.ruleSources[0], ...extra }] }),
      );
    const store = new SourceSyncStore(":memory:", 1);
    try {
      store.record(
        "one",
        0,
        "needs-conversion",
        {
          source: "one",
          hash: "a",
          status: "needs-conversion",
          version: "1",
          license: "Apache-2.0",
          tests: 0,
        },
        new Uint8Array([1]),
      );
      assert.throws(
        () =>
          store.record(
            "two",
            1,
            "needs-conversion",
            {
              source: "two",
              hash: "b",
              status: "needs-conversion",
              version: "1",
              license: "Apache-2.0",
              tests: 0,
            },
            new Uint8Array([2]),
          ),
        /capacity/,
      );
      assert.equal(store.audit().length, 1);
    } finally {
      store.close();
    }
  }));

test("regression suite requires both sample classes and isolates cached decisions", async () => {
  const loaded = loadPolicy(policy);
  assert.equal(await verifySourcePolicy(loaded, samples), 2);
  await assert.rejects(verifySourcePolicy(loaded, [samples[0], samples[0]]), /both required/);
  await assert.rejects(
    verifySourcePolicy(loaded, [
      samples[0],
      { ...samples[1], url: "https://production.example/api" },
    ]),
    /target/,
  );
  await assert.rejects(
    verifySourcePolicy(loaded, [
      samples[0],
      { ...samples[0], url: "https://simulation.test/api?q=hello" },
    ]),
    /failed/,
  );
});
