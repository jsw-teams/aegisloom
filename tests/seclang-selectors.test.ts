import assert from "node:assert/strict";
import { test } from "node:test";
import { compileSecLang, executeSecLang } from "../packages/seclang/index.js";

const sample = (query: string) => ({
  url: `https://example.test/?${query}`,
  method: "GET",
  headers: {},
});
test("native SecLang excludes named collection members", () => {
  const program = compileSecLang(
    'SecRule ARGS|!ARGS:csrf "@contains attack" "id:20001,phase:2,deny"',
    { strict: true },
  );
  assert.equal(executeSecLang(program, sample("csrf=attack")).blocked, false);
  assert.equal(executeSecLang(program, sample("csrf=attack&q=attack")).blocked, true);
});
test("native SecLang honors case-insensitive negative collection keys", () => {
  const program = compileSecLang(
    'SecRule ARGS|!ARGS:CsRf "@contains attack" "id:20002,phase:2,deny"',
    { strict: true },
  );
  assert.equal(executeSecLang(program, sample("csrf=attack")).blocked, false);
});
test("SecLang collection-count selector counts elements", () => {
  const program = compileSecLang('SecRule &ARGS "@ge 3" "id:20003,phase:2,deny"', { strict: true });
  assert.equal(executeSecLang(program, sample("x=1&x=2&y=3")).blocked, true);
  assert.equal(executeSecLang(program, sample("x=1&y=2")).blocked, false);
});
