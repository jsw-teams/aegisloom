import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSecLangSyntax } from "../../scr/seclang/syntax.js";

test("SecLang lexer preserves empty quoted arguments", () => {
  const [rule] = parseSecLangSyntax('SecRule REQUEST_URI "" "id:1,pass"');
  assert.deepEqual(rule?.args, ["REQUEST_URI", "", "id:1,pass"]);
});

test("only an odd number of trailing backslashes continues a line", () => {
  const input = "SecMarker end\\\\\nSecMarker next";
  const statements = parseSecLangSyntax(input);
  assert.equal(statements.length, 2);
  assert.equal(statements[1]?.line, 2);
});

test("escaped delimiters are literal quotes while regex escapes are preserved", () => {
  const [rule] = parseSecLangSyntax(String.raw`SecRule ARGS "@contains \"quoted\"" "id:1,deny"`);
  assert.equal(rule?.args[1], '@contains "quoted"');
  const [regex] = parseSecLangSyntax(String.raw`SecRule ARGS "@rx \d+\s+\"test\"" "id:2,deny"`);
  assert.equal(regex?.args[1], String.raw`@rx \d+\s+"test"`);
});
