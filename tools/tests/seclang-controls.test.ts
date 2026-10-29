import assert from "node:assert/strict";
import { test } from "node:test";
import { compileSecLang, executeSecLang } from "./seclang-helpers.js";

const request = (query = "") => ({ url: `https://test/?${query}`, method: "GET", headers: {} });

test("phase indexing preserves marker order, phase-local skipAfter, chains and logging", () => {
  const program = compileSecLang(
    [
      'SecAction "id:42901,phase:1,pass,skipAfter:END"',
      'SecAction "id:42902,phase:1,pass,setvar:tx.must_skip=1"',
      'SecRule ARGS:q "@streq attack" "id:42903,phase:2,deny,chain"',
      'SecRule REQUEST_METHOD "@streq GET" "setvar:tx.chain_seen=1"',
      "SecMarker END",
      'SecAction "id:42904,phase:1,pass,setvar:tx.resumed=1"',
      'SecAction "id:42905,phase:5,pass,setvar:tx.logged=1"',
    ].join("\n"),
    { strict: true },
  );
  try {
    const attack = executeSecLang(program, request("q=attack"));
    assert.equal(attack.blocked, true);
    assert.equal(attack.tx.must_skip, undefined);
    assert.equal(attack.tx.resumed, "1");
    assert.equal(attack.tx.chain_seen, "1");
    const logged = executeSecLang(program, request("q=attack"), {
      transaction: attack.transaction,
      phases: [5],
    });
    assert.equal(logged.tx.logged, "1");
    assert.equal(executeSecLang(program, request("q=normal")).blocked, false);
  } finally {
    program.dispose();
  }
});

test("ctl runs only after the entire chain matches and is isolated per transaction", () => {
  const program = compileSecLang(
    'SecRule ARGS:exception "@streq yes" "id:42001,phase:1,pass,chain"\n' +
      'SecRule REQUEST_METHOD "@streq POST" "ctl:ruleRemoveById=42002"\n' +
      'SecRule ARGS:q "@contains attack" "id:42002,phase:2,deny"',
    { strict: true },
  );
  assert.equal(executeSecLang(program, request("exception=yes&q=attack")).blocked, true);
  assert.equal(
    executeSecLang(program, { ...request("exception=yes&q=attack"), method: "POST" }).blocked,
    false,
  );
  assert.equal(executeSecLang(program, request("q=attack")).blocked, true);
});

test("default pass makes CRS block actions score until the explicit threshold rule denies", () => {
  const program = compileSecLang(
    'SecDefaultAction "phase:2,pass,log"\n' +
      'SecAction "id:42003,phase:1,setvar:tx.threshold=5"\n' +
      'SecRule ARGS:q "@contains attack" "id:42004,block,setvar:tx.score=+5"\n' +
      'SecRule TX:score "@ge %{tx.threshold}" "id:42005,deny"',
    { strict: true },
  );
  const result = executeSecLang(program, request("q=attack"));
  assert.equal(result.blocked, true);
  assert.deepEqual(result.matched, ["42003", "42004", "42005"]);
});

test("static and transactional target exclusions preserve other arguments", () => {
  const program = compileSecLang(
    'SecAction "id:42006,phase:1,ctl:ruleRemoveTargetByTag=attack;ARGS:safe"\n' +
      'SecRule ARGS "@contains x" "id:42007,tag:attack,deny"\n' +
      'SecRuleUpdateTargetById 42007 "!ARGS:/^csrf/"',
    { strict: true },
  );
  assert.equal(executeSecLang(program, request("safe=x&csrf_token=x")).blocked, false);
  assert.equal(executeSecLang(program, request("safe=x&q=x")).blocked, true);
});

test("response phases retain TX from request phases and inspect actual response data", () => {
  const program = compileSecLang(
    'SecAction "id:42008,phase:1,setvar:tx.initialized=1"\n' +
      'SecRule RESPONSE_BODY "@contains secret" "id:42009,phase:4,deny"',
    { strict: true },
  );
  const input = request();
  const before = executeSecLang(program, input);
  const after = executeSecLang(
    program,
    { ...input, responseStatus: 200, responseBody: "secret" },
    { phases: [3, 4, 5], transaction: before.transaction },
  );
  assert.equal(before.blocked, false);
  assert.equal(after.blocked, true);
  assert.equal(after.tx.initialized, "1");
});

test("JSON and XML processors provide real field values to rules", () => {
  const json = compileSecLang('SecRule ARGS:json.q "@contains attack" "id:42010,deny"', {
    strict: true,
  });
  assert.equal(
    executeSecLang(json, {
      ...request(),
      method: "POST",
      headers: { "content-type": "application/json" },
      bodyText: '{"q":"attack"}',
    }).blocked,
    true,
  );
  const xml = compileSecLang('SecRule XML:/* "@contains attack" "id:42011,deny"', { strict: true });
  assert.equal(
    executeSecLang(xml, {
      ...request(),
      method: "POST",
      headers: { "content-type": "application/xml" },
      bodyText: "<root><q>attack</q></root>",
    }).blocked,
    true,
  );
});

test("multiMatch inspects input before a transformation removes the attack", () => {
  const program = compileSecLang(
    'SecRule ARGS "@contains YX" "id:42012,deny,multiMatch,t:base64Decode"',
    { strict: true },
  );
  assert.equal(executeSecLang(program, request("q=YXR0YWNr")).blocked, true);
});
test("global SecLang firewall directives change actual execution and never silently discard source rules", () => {
  const request = {
    url: "https://test/?q=attack",
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    bodyText: "q=attack",
  };
  for (const directive of [
    "SecRuleEngine Off",
    "SecRuleEngine DetectionOnly",
    "SecRuleRemoveById 49001",
  ]) {
    const vm = compileSecLang(`${directive}\nSecRule ARGS:q "@streq attack" "id:49001,deny"`, {
      strict: true,
    });
    try {
      const result = executeSecLang(vm, request);
      assert.equal(vm.sourceRules, 1);
      assert.equal(vm.supportedRules, 1);
      assert.equal(result.blocked, false);
      if (directive.endsWith("DetectionOnly")) assert.ok(result.matched.includes("49001"));
    } finally {
      vm.dispose();
    }
  }
  const vm = compileSecLang(
    'SecRequestBodyAccess Off\nSecRule ARGS_POST:q "@streq attack" "id:49002,deny"',
    { strict: true },
  );
  try {
    assert.equal(executeSecLang(vm, request).blocked, false);
  } finally {
    vm.dispose();
  }
});

test("SecRequestBodyLimit zero removes the rule-configured cap while the host hard limit remains enforced", () => {
  const input = {
    url: "https://test/",
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    bodyText: "q=attack",
  };
  for (const limit of ["0", "4", "4\nSecRequestBodyLimit 0"]) {
    const program = compileSecLang(
      `SecRequestBodyLimit ${limit}\nSecRule ARGS_POST:q "@streq attack" "id:49003,deny"`,
      { strict: true, requestBodyLimit: 64 },
    );
    try {
      const result = executeSecLang(program, input);
      assert.equal(result.transaction.bodyParseError, limit === "4");
      assert.equal(result.matched.includes("49003"), limit !== "4");
    } finally {
      program.dispose();
    }
  }
});
