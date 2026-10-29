import assert from "node:assert/strict";
import { test } from "node:test";
import { compileSecLang, executeSecLang } from "./seclang-helpers.js";

const request = (query: string) => ({
  url: `https://example.test/?${query}`,
  method: "GET",
  headers: {},
});

test("capture exposes regex groups to setvar and later chain members", () => {
  const program = compileSecLang(
    'SecRule ARGS:q "@rx ^(attack)-(\\d+)$" "id:30001,phase:2,deny,capture,chain,setvar:tx.number=%{tx.2}"\n' +
      'SecRule TX:number "@eq %{tx.limit}"',
    { strict: true },
  );
  const result = executeSecLang(program, request("q=attack-42"), { tx: { limit: 42 } });
  assert.equal(result.blocked, true);
  assert.equal(result.tx["0"], "attack-42");
  assert.equal(result.tx["1"], "attack");
  assert.equal(result.tx.number, "42");
});

test("setvar runs for each matching target and persists if a later chain member fails", () => {
  const program = compileSecLang(
    'SecRule ARGS "@contains x" "id:30002,phase:2,deny,chain,setvar:tx.score=+1"\n' +
      'SecRule REQUEST_METHOD "@streq POST"',
    { strict: true },
  );
  const result = executeSecLang(program, request("a=x&b=x&c=y"));
  assert.equal(result.blocked, false);
  assert.equal(result.tx.score, 2);
});

test("unsupported macro and capture forms fail compilation", () => {
  assert.throws(
    () =>
      compileSecLang('SecRule ARGS "@rx %{unknown.pattern}" "id:1,capture,deny"', { strict: true }),
    /Unsupported macro/,
  );
  const program = compileSecLang('SecRule ARGS "@contains x" "id:1,capture,deny"', {
    strict: true,
  });
  const result = executeSecLang(program, request("q=x"));
  assert.equal(result.blocked, true);
  assert.equal(result.tx["0"], undefined);
});

test("SecAction initializes TX state before later rules in the same phase", () => {
  const program = compileSecLang(
    'SecAction "id:30003,phase:1,pass,setvar:tx.threshold=5"\n' +
      'SecRule TX:threshold "@eq 5" "id:30004,phase:1,deny"',
    { strict: true },
  );
  const result = executeSecLang(program, request(""));
  assert.equal(result.blocked, true);
  assert.equal(result.tx.threshold, "5");
  assert.deepEqual(result.matched, ["30003", "30004"]);
});

test("SecAction cannot truncate or join a chained rule", () => {
  assert.throws(
    () =>
      compileSecLang(
        'SecRule ARGS "@contains x" "id:30005,chain,pass"\nSecAction "id:30006,pass"',
        { strict: true },
      ),
    /SecAction cannot participate/,
  );
});

test("phase 1 does not inspect the request body or its form arguments", () => {
  const source =
    'SecRule ARGS "@contains attack" "id:30007,phase:1,deny"\n' +
    'SecRule REQUEST_BODY "@contains attack" "id:30008,phase:1,deny"\n' +
    'SecRule ARGS "@contains attack" "id:30009,phase:2,deny"';
  const program = compileSecLang(source, { strict: true });
  const input = {
    ...request(""),
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    bodyText: "q=attack",
  };
  assert.equal(executeSecLang(program, input, { phases: [1] }).blocked, false);
  assert.deepEqual(executeSecLang(program, input).matched, ["30009"]);
});

test("TX reads preserve body processing after controls enable parsing within phase 2", () => {
  const program = compileSecLang(
    'SecAction "id:30010,phase:1,pass,ctl:requestBodyAccess=Off,setvar:tx.ready=1"\n' +
      'SecAction "id:30011,phase:2,pass,ctl:requestBodyAccess=On,ctl:requestBodyProcessor=JSON"\n' +
      'SecRule TX:ready "@eq 1" "id:30012,phase:2,pass,setvar:tx.error=%{REQBODY_ERROR}"\n' +
      'SecRule TX:error "@eq 1" "id:30013,phase:2,deny"',
    { strict: true },
  );
  const result = executeSecLang(program, {
    ...request(""),
    method: "POST",
    headers: { "content-type": "application/octet-stream" },
    bodyText: "invalid JSON",
  });
  assert.equal(result.blocked, true);
  assert.equal(result.tx.error, "1");
});

test("native variable macros resolve request collections and response values at their actual phase", () => {
  const program = compileSecLang(
    'SecAction "id:30014,phase:1,pass,setvar:tx.uri=%{REQUEST_URI},setvar:tx.argument=%{ARGS_GET.q},setvar:tx.cookie=%{REQUEST_COOKIES.token},setvar:tx.early=%{RESPONSE_STATUS}"\n' +
      'SecAction "id:30015,phase:3,pass,setvar:tx.status=%{RESPONSE_STATUS},setvar:tx.type=%{RESPONSE_HEADERS.content-type}"\n' +
      'SecRule TX:status "@eq 200" "id:30016,phase:4,deny,chain"\n' +
      'SecRule TX:type "@streq application/json"',
    { strict: true },
  );
  const result = executeSecLang(
    program,
    {
      ...request("q=One"),
      headers: { cookie: "token=Abc" },
      responseStatus: 200,
      responseHeaders: { "content-type": "application/json" },
    },
    { phases: [1, 2, 3, 4] },
  );
  assert.equal(result.blocked, true);
  assert.equal(result.tx.uri, "/?q=One");
  assert.equal(result.tx.argument, "One");
  assert.equal(result.tx.cookie, "Abc");
  assert.equal(result.tx.early, "");
  assert.equal(result.tx.status, "200");
});
