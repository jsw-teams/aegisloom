import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { applySources } from "../packages/control-plane/source-apply.js";
import { loadPolicy } from "../packages/rule-ir/index.js";
import { createHeaderPolicy } from "../packages/runtime/header-policy.js";
import { attackRule, context } from "./helpers.js";

const normal = {
  name: "normal",
  kind: "legitimate",
  url: "https://simulation.test/api?q=hello",
  expectedStatus: 204,
};
const attack = {
  name: "attack",
  kind: "attack",
  url: "https://simulation.test/api?q=attack",
  expectedStatus: 403,
};
test("automatic application merges public/private policies, enforces them, removes withdrawn rules and preserves last good on failure", async () => {
  const dir = await mkdtemp(join(tmpdir(), "shield-apply-"));
  const path = (name: string) => join(dir, name);
  const privateRule = {
    ...attackRule,
    id: "private",
    when: { field: "query", key: "q", op: "eq", value: "private" },
  };
  const privateAttack = {
    ...attack,
    name: "private",
    url: "https://simulation.test/api?q=private",
  };
  const config = {
    version: "1",
    upstreams: [],
    permittedLicenses: ["Apache-2.0"],
    application: {
      policyFile: "active.json",
      baselineFile: "baseline.json",
      regressionFile: "all.json",
      service: "api",
    },
    ruleSources: [
      {
        id: "public",
        enabled: true,
        autoApply: true,
        location: "https://api.github.com/repos/owner/rules/contents/policy.json",
        format: "shield-ir",
        version: "main",
        license: "Apache-2.0",
        service: "api",
        regressionFile: "public.json",
      },
      {
        id: "private",
        enabled: true,
        autoApply: true,
        location: "private.json",
        format: "shield-ir",
        version: "main",
        license: "Apache-2.0",
        service: "api",
        regressionFile: "private-tests.json",
      },
    ],
  };
  const transport: typeof fetch = async () =>
    new Response(JSON.stringify({ version: "1", rules: [attackRule] }));
  try {
    await writeFile(path("sources.json"), JSON.stringify(config));
    await writeFile(path("baseline.json"), JSON.stringify({ version: "1", rules: [] }));
    await writeFile(path("private.json"), JSON.stringify({ version: "1", rules: [privateRule] }));
    await writeFile(path("public.json"), JSON.stringify([normal, attack]));
    await writeFile(path("private-tests.json"), JSON.stringify([normal, privateAttack]));
    await writeFile(path("all.json"), JSON.stringify([normal, attack, privateAttack]));
    assert.equal((await applySources(path("sources.json"), transport)).applied, true);
    const saved = await readFile(path("active.json"), "utf8");
    const gate = createHeaderPolicy(loadPolicy(saved), "api");
    assert.equal(gate(new Request(privateAttack.url), context), "private");
    assert.equal(gate(new Request(attack.url), context), attackRule.id);
    assert.equal(gate(new Request(normal.url), context), undefined);
    assert.equal((await applySources(path("sources.json"), transport)).applied, false);
    await assert.rejects(
      applySources(path("sources.json"), async () => new Response(null, { status: 503 })),
    );
    assert.equal(await readFile(path("active.json"), "utf8"), saved);
    await writeFile(path("public.json"), JSON.stringify([normal, { ...attack, url: normal.url }]));
    await assert.rejects(applySources(path("sources.json"), transport), /regression/);
    assert.equal(await readFile(path("active.json"), "utf8"), saved);
    config.ruleSources[0]!.enabled = false;
    await writeFile(path("sources.json"), JSON.stringify(config));
    await writeFile(path("all.json"), JSON.stringify([normal, privateAttack]));
    await applySources(path("sources.json"), transport);
    assert.deepEqual(
      loadPolicy(await readFile(path("active.json"), "utf8")).rules.map((rule) => rule.id),
      ["private"],
    );
    config.application.policyFile = "./private.json";
    await writeFile(path("sources.json"), JSON.stringify(config));
    await assert.rejects(applySources(path("sources.json"), transport), /overwrite/);
    config.application.policyFile = "active.json";
    await writeFile(path("sources.json"), JSON.stringify(config));
    await writeFile(path("active.json.apply-lock"), "other writer");
    await assert.rejects(applySources(path("sources.json"), transport), /EEXIST/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("header admission leaves binary bodies untouched and rejects unsupported rule semantics", async () => {
  const gate = createHeaderPolicy(loadPolicy({ version: "1", rules: [attackRule] }), "api");
  const request = new Request("https://simulation.test/api?q=hello", {
    method: "POST",
    body: new Uint8Array([255, 0, 128]),
  });
  assert.equal(gate(request, context), undefined);
  assert.deepEqual(new Uint8Array(await request.arrayBuffer()), new Uint8Array([255, 0, 128]));
  assert.throws(
    () =>
      createHeaderPolicy(
        loadPolicy({ version: "1", rules: [{ ...attackRule, then: { action: "challenge" } }] }),
        "api",
      ),
    /stateless/,
  );
  assert.throws(
    () =>
      createHeaderPolicy(
        loadPolicy({
          version: "1",
          rules: [{ ...attackRule, when: { field: "identity", op: "exists", value: true } }],
        }),
        "api",
      ),
    /observable/,
  );
});
