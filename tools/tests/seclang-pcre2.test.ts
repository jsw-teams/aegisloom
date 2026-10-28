import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import {
  compileSecLang,
  createPCRE2Backend,
  executeSecLang,
  PCRE2Error,
} from "./seclang-helpers.js";

const binary = await readFile(new URL("../../scr/seclang/vendor/pcre2.wasm", import.meta.url));
const backend = await createPCRE2Backend(binary);

test("PCRE2 runs lookbehind, backreferences and captures in the native SecLang VM", () => {
  const program = compileSecLang(
    'SecRule ARGS "@rx (?<=prefix:)([a-z]+)-\\1$" "id:40001,phase:2,deny,capture"',
    { strict: true, regexBackend: backend },
  );
  const result = executeSecLang(program, { url: "https://test/?q=prefix:abc-abc", method: "GET" });
  assert.equal(result.blocked, true);
  assert.equal(result.tx["0"], "abc-abc");
  assert.equal(result.tx["1"], "abc");
  assert.equal(
    executeSecLang(program, { url: "https://test/?q=prefix:abc-def", method: "GET" }).blocked,
    false,
  );
});

test("PCRE2 accepts a precompiled module and enforces actual backtracking limits", async () => {
  const backend = await createPCRE2Backend(await WebAssembly.compile(binary), {
    matchLimit: 100,
    depthLimit: 100,
  });
  const pattern = backend.compile("(*NO_AUTO_POSSESS)(*NO_START_OPT)^(a+)+$");
  assert.throws(() => pattern.matcher(`${"a".repeat(30)}!`).find(), PCRE2Error);
  pattern.destroy?.();
  assert.throws(() => pattern.matcher("a").find(), /destroyed/);
});
