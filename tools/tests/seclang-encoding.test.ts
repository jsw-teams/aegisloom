import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { utf8Bytes } from "../../scr/seclang/bytes.js";
import { transform } from "../../scr/seclang/transforms.js";
import { compileSecLang, createPCRE2Backend, executeSecLang } from "./seclang-helpers.js";

const backend = await createPCRE2Backend(
  await readFile(new URL("../../scr/seclang/vendor/pcre2.wasm", import.meta.url)),
);
const send = (source: string, query: string) =>
  executeSecLang(compileSecLang(source, { strict: true, regexBackend: backend }), {
    url: `https://test/?${query}`,
    method: "GET",
  });

test("percent-encoded invalid UTF-8 reaches the validation operator without replacement", () => {
  assert.equal(send('SecRule ARGS "@validateUtf8Encoding" "id:43001,deny"', "q=%ff").blocked, true);
  assert.equal(
    send('SecRule ARGS "@validateUtf8Encoding" "id:43001,deny"', `q=${encodeURIComponent("你好")}`)
      .blocked,
    false,
  );
});

test("transforms operate on bytes including embedded NUL, Unicode and SHA1 output", () => {
  assert.equal(transform(utf8Bytes("你好"), ["length"]), "6");
  assert.equal(transform(utf8Bytes("你好"), ["hexencode"]), "e4bda0e5a5bd");
  assert.equal(transform(utf8Bytes("你好"), ["utf8tounicode"]), "%u4f60%u597d");
  assert.equal(transform("abc", ["sha1", "hexencode"]), "a9993e364706816aba3e25717850c26c9cd0d89d");
  assert.equal(transform("%00%ff+%broken", ["urldecode"]), "\x00\xff %broken");
});

test("PCRE2 captures preserve non-ASCII bytes through TX and later transformations", () => {
  const source =
    'SecRule ARGS:q "@rx (.+)" "id:43002,pass,capture,setvar:tx.saved=%{tx.1}"\n' +
    'SecRule TX:saved "@streq e4bda0e5a5bd" "id:43003,deny,t:hexEncode"';
  assert.equal(send(source, `q=${encodeURIComponent("你好")}`).blocked, true);
});

test("dynamic regex operands use current transaction state and are disposed with the program", () => {
  const program = compileSecLang(
    'SecAction "id:43004,phase:1,setvar:tx.pattern=^attack$"\nSecRule ARGS "@rx %{tx.pattern}" "id:43005,capture,deny"',
    { strict: true, regexBackend: backend },
  );
  assert.equal(
    executeSecLang(program, { url: "https://test/?q=attack", method: "GET" }).blocked,
    true,
  );
  program.dispose();
  assert.throws(() => executeSecLang(program, { url: "https://test/", method: "GET" }), /disposed/);
});
