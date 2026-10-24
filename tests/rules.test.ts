import assert from "node:assert/strict";
import { test } from "node:test";
import { compileExpression } from "../packages/core/matcher.js";
import { duration, explain, loadPolicy, policyVersion } from "../packages/rule-ir/index.js";
import { attackRule, context, request } from "./helpers.js";

test("YAML sugar has validated frequency semantics and readable explanation", () => {
  const p = loadPolicy(
    `version: "1"\nrules:\n  - id: login\n    name: 保护登录接口\n    service: api\n    when:\n      path: /api/login\n      method: POST\n      requests:\n        moreThan: 20\n        within: 1m\n        groupBy: verifiedClientIp\n    then:\n      action: rate-limit\n      duration: 10m\n`,
  );
  assert.equal(p.rules[0]?.requests?.moreThan, 20);
  assert.match(explain(p.rules[0]!), /20\/1m/);
  assert.equal(duration("10m"), 600000);
});
test("schema, duplicates, aliases, regex and conflicts fail loudly", () => {
  for (const rule of [
    { ...attackRule, unknown: true },
    { ...attackRule, when: { field: "query", op: "eq", value: "x" } },
    { ...attackRule, when: { field: "path", op: "regex", value: "(a)\\1" } },
    { ...attackRule, when: { field: "path", op: "regex", value: "a{99999}" } },
    { ...attackRule, then: { action: "rate-limit" } },
    { ...attackRule, expiresAt: "tomorrow" },
    { ...attackRule, then: { action: "block", duration: "1m" } },
    { ...attackRule, then: { action: "block", score: 30 } },
    { ...attackRule, when: { field: "path", op: "eq", value: "/api", min: 1 } },
    { ...attackRule, when: { field: "path", op: "range", value: "/api", min: 1 } },
  ])
    assert.throws(() => loadPolicy({ version: "1", rules: [rule] }));
  assert.throws(
    () =>
      loadPolicy({
        version: "1",
        rules: [attackRule, { ...attackRule, id: "conflict", then: { action: "detect" } }],
      }),
    /Conflict/,
  );
  assert.throws(() => loadPolicy("version: '1'\nversion: '1'\nrules: []"));
  assert.throws(() => loadPolicy("version: '1'\nrules: &rules [*rules]"));
  assert.throws(() => loadPolicy({ version: "1", rules: [attackRule, attackRule] }), /Duplicate/);
});
test("AND OR NOT, transforms, query duplicates, existence and numeric ranges", () => {
  const req = request("?x=0&x=21&encoded=%2520BAD%2520");
  const input = { request: req, url: new URL(req.url), path: "/api", bodyText: "", context };
  const match = compileExpression({
    all: [
      { field: "query", key: "x", op: "range", min: 20, max: 22 },
      {
        field: "query",
        key: "encoded",
        op: "eq",
        value: "bad",
        transforms: ["urlDecode", "trim", "lowercase"],
      },
      {
        any: [
          { field: "method", op: "eq", value: "POST" },
          { not: { field: "header", key: "x-foo", op: "exists", value: true } },
        ],
      },
    ],
  });
  assert.equal(match(input), true);
});
test("policy hash stable across serialize/reload; no arbitrary code", async () => {
  const p = loadPolicy({ version: "1", rules: [attackRule] });
  assert.equal(await policyVersion(p), await policyVersion(loadPolicy(JSON.stringify(p))));
  assert.throws(() =>
    loadPolicy({ version: "1", rules: [{ ...attackRule, when: { script: "process.exit()" } }] }),
  );
});
