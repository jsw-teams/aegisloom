import assert from "node:assert/strict";
import { test } from "node:test";
import { convert } from "../src/index.mjs";
const metadata = { url: "operator-authored:test", version: "1", license: "Apache-2.0", service: "api", format: "seclang" };
const simple = 'SecRule REQUEST_METHOD "@streq DELETE" "id:100,phase:1,deny,t:none,msg:\'Block DELETE\'"';
test("exact scalar SecLang conversion retains pinned provenance", () => {
  const report = convert(simple, metadata);
  assert.equal(report.status, "exact"); assert.equal(report.policy.rules[0].when.value, "DELETE");
  assert.match(report.source.sha256, /^[a-f0-9]{64}$/); assert.equal(report.policy.rules[0].provenance.license, "Apache-2.0");
});
test("chains, CRS state/PCRE, missing reset, scripts and active templates cannot silently lose semantics", () => {
  for (const source of [simple.replace("t:none", "t:lowercase"), simple.replace("REQUEST_METHOD", "REQUEST_URI"), simple.replace("deny,t:none", "deny,t:none,chain"), simple.replace("deny,t:none", "deny,t:none,setvar:tx.score=+5"), "SecAction \"exec:/bin/sh\"", simple.replace("@streq DELETE", "@rx (a)\\1")]) assert.notEqual(convert(source, metadata).status, "exact");
  assert.equal(convert(simple, { ...metadata, format: "nuclei" }).status, "unsupported");
  assert.equal(convert(`${simple}\nSecAction \"unsupported\"`, metadata).status, "partial");
  assert.throws(() => convert(simple, { ...metadata, sha256: "0".repeat(64) }), /checksum/);
});
test("CrowdSec detection is partial because alert/scenario semantics differ", () => {
  const report = convert("name: operator/method\nrules:\n - zones: [METHOD]\n   match:\n     type: equals\n     value: DELETE\n", { ...metadata, format: "crowdsec-appsec" });
  assert.equal(report.status, "partial"); assert.equal(report.policy.rules[0].then.action, "detect");
  assert.ok(report.limitations.some((s) => s.includes("NOT reproduced")));
});
