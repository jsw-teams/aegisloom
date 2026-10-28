import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";
import { compileSecLang, executeSecLang, splitActions } from "../src/seclang-vm.mjs";

const req = (url, method = "GET", headers = {}) => ({ url, method, headers });
test("first-party SecLang method deny and phase separation", () => {
  const program = compileSecLang(
    'SecRule REQUEST_METHOD "@streq DELETE" "id:100,phase:1,deny,t:none"',
    { strict: true },
  );
  assert.equal(program.supportedRules, 1);
  assert.deepEqual(executeSecLang(program, req("https://api.test/", "GET")).matched, []);
  assert.equal(executeSecLang(program, req("https://api.test/", "DELETE")).blocked, true);
  assert.equal(executeSecLang(program, req("https://api.test/", "DELETE"), { phases: [2] }).blocked, false);
});
test("TX chain is atomic and phase is inherited by child rules", () => {
  const input = [
    'SecRule REQUEST_METHOD "@streq POST" "id:1001,phase:1,pass,chain"',
    'SecRule REQUEST_HEADERS:User-Agent "@contains scanner" "t:lowercase,setvar:tx.anomaly_score=+5"',
    'SecRule TX:anomaly_score "@ge 5" "id:1002,phase:1,deny,status:406"',
  ].join("\n");
  const program = compileSecLang(input, { strict: true });
  const blocked = executeSecLang(program, req("https://api.test/", "POST", { "user-agent": "ScannerBot" }));
  assert.equal(blocked.blocked, true);
  assert.equal(blocked.status, 406);
  assert.deepEqual(blocked.matched, ["1001", "1002"]);
  assert.equal(blocked.tx.anomaly_score, 5);
  const ordinary = executeSecLang(program, req("https://api.test/", "POST", { "user-agent": "Browser" }));
  assert.equal(ordinary.blocked, false);
  assert.equal(ordinary.tx.anomaly_score, undefined);
});
test("phase 2, URL decoding and phrases are matched using first-party engine", () => {
  const program = compileSecLang([
    'SecRule ARGS "@rx union +select" "id:301,phase:2,deny,t:none,t:lowercase"',
    'SecRule REQUEST_HEADERS:User-Agent "@pmFromFile probes.data" "id:302,phase:1,deny"',
  ].join("\n"), { phraseFiles: { "probes.data": ["masscan", "nikto"] }, strict: true });
  assert.equal(executeSecLang(program, req("https://api.test/?q=UNION%20SELECT")).blocked, true);
  assert.equal(executeSecLang(program, req("https://api.test/", "GET", { "user-agent": "nikto/2.5" })).blocked, true);
  assert.equal(executeSecLang(program, req("https://api.test/?q=hello")).blocked, false);
});
test("SecMarker and skipAfter skip numbered rules but not later rules", () => {
  const program = compileSecLang([
    'SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:913011,phase:1,pass,skipAfter:END-913"',
    'SecRule REQUEST_URI "@contains admin" "id:913100,phase:1,deny"',
    "SecMarker END-913",
    'SecRule REQUEST_URI "@contains later" "id:913200,phase:1,deny"',
  ].join("\n"), { strict: true });
  const initial = { DETECTION_PARANOIA_LEVEL: 1 };
  assert.equal(executeSecLang(program, req("https://api.test/admin"), { tx: initial, phases: [1] }).blocked, false);
  assert.equal(executeSecLang(program, req("https://api.test/later"), { tx: initial, phases: [1] }).blocked, true);
  assert.equal(executeSecLang(program, req("https://api.test/admin"), { tx: { DETECTION_PARANOIA_LEVEL: 2 }, phases: [1] }).blocked, true);
});
test("unknown actions, unproven PCRE, Unicode transforms and partial chains fail closed", () => {
  const bad = [
    'SecRule ARGS "@rx (?<=foo)bar" "id:1,phase:2,deny"',
    'SecRule ARGS "@streq x" "id:1,phase:2,deny,t:urlDecodeUni"',
    'SecRule ARGS "@streq x" "id:1,phase:2,deny,ctl:ruleRemoveById=100"',
    'SecRule ARGS "@streq x" "id:1,phase:2,chain,deny"',
    'SecRule XML "@streq x" "id:1,phase:2,deny"',
    'SecRule ARGS|!ARGS:token "@streq x" "id:1,phase:2,deny"',
  ];
  for (const source of bad) {
    const report = compileSecLang(source);
    assert.ok(report.unsupported.length > 0, source);
    assert.throws(() => executeSecLang(report, req("https://api.test/?x=y")), /incompletely compiled/);
    assert.throws(() => compileSecLang(source, { strict: true }), /unsupported/i);
  }
});
test("action list preserves comma-separated quoted text and chaining", () => {
  assert.deepEqual(splitActions("id:12,msg:'a,b',phase:1,setvar:tx.score=+5"), [
    "id:12", "msg:'a,b'", "phase:1", "setvar:tx.score=+5",
  ]);
});
test("real CRS corpus compiles with a precise unsupported-semantics report", () => {
  const dir = new URL("../../rules/upstream/crs/", import.meta.url);
  let compiled = 0, total = 0, rejected = 0;
  for (const file of readdirSync(dir).filter((name) => name.endsWith(".conf"))) {
    const program = compileSecLang(readFileSync(new URL(file, dir), "utf8"));
    compiled += program.supportedRules;
    total += program.sourceRules;
    rejected += program.unsupported.length;
    assert.ok(program.sourceRules > 0, file);
    assert.ok(program.unsupported.every((entry) => entry.line > 0), file);
  }
  assert.ok(total >= 240);
  assert.ok(compiled > 0, "real corpus should compile at least some genuine rules");
  assert.ok(rejected > 0, "an incomplete runtime must not claim full CRS compatibility");
  console.log(JSON.stringify({ realCrsRuleStatements: total, supportedRootRules: compiled, rejectedFeatures: rejected }));
});
