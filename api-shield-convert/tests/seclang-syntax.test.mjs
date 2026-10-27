import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { parseSecLangSyntax } from "../src/seclang-syntax.mjs";

test("all archived OWASP CRS files are lexed as complete logical statements", () => {
  const dir = new URL("../../rules/upstream/crs/", import.meta.url);
  let count = 0;
  for (const name of readdirSync(dir).filter((name) => name.endsWith(".conf"))) {
    const statements = parseSecLangSyntax(readFileSync(new URL(name, dir), "utf8"));
    assert.ok(statements.length > 0, name);
    assert.ok(statements.every((part) => part.directive && part.line > 0), name);
    count += statements.filter((part) => part.directive === "SecRule").length;
  }
  assert.ok(count >= 240, "Expected all CRS rule declarations");
});
test("multiline quotes and escaping stay in the parsed source", () => {
  const sample = 'SecRule REQUEST_HEADERS:User-Agent "@contains x" \\\n "id:930001,phase:1,deny,msg:\'test rule\'"';
  const parsed = parseSecLangSyntax(sample);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].directive, "SecRule");
  assert.equal(parsed[0].args[0], "REQUEST_HEADERS:User-Agent");
  assert.ok(parsed[0].args[2].includes("phase:1"));
});
test("invalid quoting and dangling continuation fail closed", () => {
  assert.throws(() => parseSecLangSyntax('SecRule METHOD "unterminated'), /quote/);
  assert.throws(() => parseSecLangSyntax("SecRule REQUEST_METHOD \\"), /continuation/);
});
