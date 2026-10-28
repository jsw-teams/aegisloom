import assert from "node:assert/strict";
import { test } from "node:test";
import { compileSecLang, executeSecLang } from "./seclang-helpers.js";

test("MATCHED_VARS contains the previous operator check, without matches leaking from earlier rules", () => {
  const program = compileSecLang(
    'SecRule ARGS:earlier "@streq yes" "id:44001,pass"\nSecRule ARGS:q "@contains \'" "id:44002,deny,chain"\nSecRule MATCHED_VARS "!@rx [0-9]\\x27[0-9]"',
    { strict: true },
  );
  try {
    const send = (q: string) =>
      executeSecLang(program, {
        url: `https://test/?earlier=yes&q=${encodeURIComponent(q)}`,
        method: "GET",
      });
    assert.equal(send("1'000'000").blocked, false);
    assert.equal(send("a'bad'c").blocked, true);
  } finally {
    program.dispose();
  }
});
test("REQUEST_FILENAME decodes octets once, preserves plus signs, and REQUEST_URI_RAW preserves its encoding", () => {
  const program = compileSecLang(
    'SecRule REQUEST_FILENAME "@streq /path/你好+file" "id:44003,pass,setvar:tx.filename=1"\nSecRule REQUEST_URI_RAW "@contains %E4%BD%A0" "id:44004,deny"',
    { strict: true },
  );
  try {
    const result = executeSecLang(program, {
      url: "https://test/path/%E4%BD%A0%E5%A5%BD+file",
      method: "GET",
    });
    assert.equal(result.tx.filename, "1");
    assert.equal(result.blocked, true);
  } finally {
    program.dispose();
  }
});
