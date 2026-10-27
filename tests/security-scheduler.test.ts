import assert from "node:assert/strict";
import { test } from "node:test";
import { refreshSecurityCandidates } from "../deploy/cloudflare/security-scheduler.js";

const policy = JSON.stringify({
  version: "1", rules: [{
    id: "marker", name: "Block marker", service: "api",
    when: { field: "query", key: "q", op: "eq", value: "bad" },
    then: { action: "block" },
  }],
});
const regressions = JSON.stringify([
  { name: "attack", kind: "attack", url: "https://simulation.test/api?q=bad", expectedStatus: 403 },
  { name: "normal", kind: "legitimate", url: "https://simulation.test/api?q=good", expectedStatus: 204 },
]);
const when = Date.parse("2026-10-27T00:00:00Z");

test("scheduled cloud rule updates are tested and staged, never made active", async () => {
  const updates: Array<{ key: string; content: string }> = [];
  const env = {
    SERVICE: "api",
    RULE_SOURCE_URL: "https://example.test/approved.json",
    RULE_REGRESSIONS: regressions,
    SECURITY_KV: {
      async put(key: string, content: string) { updates.push({ key, content }); },
    },
  };
  const result = await refreshSecurityCandidates(env, async (input) => {
    assert.equal(String(input), env.RULE_SOURCE_URL);
    return new Response(policy);
  }, when);
  assert.equal(result.rules, "verified-awaiting-approval");
  assert.equal(updates.length, 1);
  assert.equal(updates[0]!.key, "candidates/rules/latest");
  const staged = JSON.parse(updates[0]!.content);
  assert.equal(staged.tests, 2);
  assert.equal(staged.deployed, false);
  assert.equal(staged.policy.rules[0].id, "marker");
});

test("scheduled rule update rejects absent evidence and unsupported sources", async () => {
  await assert.rejects(refreshSecurityCandidates({
    SERVICE: "api",
    RULE_SOURCE_URL: "https://example.test/rules.json",
    SECURITY_KV: { async put() { throw new Error("should not write"); } },
  }), /RULE_REGRESSIONS/);
  await assert.rejects(refreshSecurityCandidates({
    SERVICE: "api",
    RULE_SOURCE_URL: "http://example.test/rules.json",
    RULE_REGRESSIONS: regressions,
    SECURITY_KV: { async put() { throw new Error("should not write"); } },
  }), /HTTPS/);
});

test("scheduled CVE scan creates only an explicitly scoped temporary isolation candidate", async () => {
  const updates: Array<{ key: string; content: string }> = [];
  const env = {
    SERVICE: "api",
    CVE_INVENTORY: JSON.stringify({ components: [{
      name: "widget", version: "1.0.0", ecosystem: "npm",
    }] }),
    CVE_EMERGENCY_PATHS: JSON.stringify({ "npm:widget": ["/api/widget"] }),
    SECURITY_KV: {
      async put(key: string, content: string) { updates.push({ key, content }); },
    },
  };
  const result = await refreshSecurityCandidates(env, async (input) => {
    assert.equal(String(input), "https://api.osv.dev/v1/query");
    return Response.json({ vulns: [{
      id: "CVE-2026-12345", modified: "2026-10-26T01:00:00Z",
      affected: [{ package: { name: "widget", ecosystem: "npm" }, versions: ["1.0.0"] }],
    }] });
  }, when);
  assert.equal(result.cve, "review-required:1");
  const staged = JSON.parse(updates[0]!.content);
  assert.equal(staged.deployed, false);
  assert.equal(staged.findings[0].candidate.classification, "feature-isolation");
  assert.equal(staged.findings[0].candidate.rule.expiresAt, "2026-10-27T01:00:00.000Z");
});
