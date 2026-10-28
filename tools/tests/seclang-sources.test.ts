import assert from "node:assert/strict";
import { test } from "node:test";
import { compileSecLang, executeSecLang } from "./seclang-helpers.js";

test("Include expands source-relative files in order, and phrase files retain source scope", () => {
  const files = {
    "first/rules.conf": 'SecRule ARGS "@pmFromFile phrases.data" "id:44001,deny"',
    "first/phrases.data": "# source one\nattack\n",
    "second/rules.conf": 'SecRule ARGS "@pmFromFile phrases.data" "id:44002,deny"',
    "second/phrases.data": "# source two\nmalware\n",
  };
  const program = compileSecLang("Include first/*.conf\nInclude second/*.conf", {
    strict: true,
    files,
  });
  const request = (q: string) => ({ url: `https://test/?q=${q}`, method: "GET" });
  assert.deepEqual(executeSecLang(program, request("attack")).matched, ["44001"]);
  assert.deepEqual(executeSecLang(program, request("malware")).matched, ["44002"]);
  assert.equal(executeSecLang(program, request("normal")).blocked, false);
});

test("required missing Includes, cycles and traversal fail before execution", () => {
  assert.throws(
    () => compileSecLang("Include missing.conf", { strict: true }),
    /Missing SecLang Include/,
  );
  assert.throws(
    () =>
      compileSecLang("Include nested.conf", {
        strict: true,
        files: { "nested.conf": "Include main.conf", "main.conf": "Include nested.conf" },
      }),
    /Cyclic/,
  );
  assert.throws(() => compileSecLang("Include ../escape.conf", { strict: true }), /escapes bundle/);
});
