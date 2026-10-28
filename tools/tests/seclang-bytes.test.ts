import assert from "node:assert/strict";
import { test } from "node:test";
import { asciiLower, octets, utf8Bytes } from "../../scr/seclang/bytes.js";

test("ASCII fast path preserves NUL and control bytes; Unicode retains UTF-8 and surrogate replacement", () => {
  const ascii = String.fromCharCode(...Array.from({ length: 128 }, (_, i) => i));
  assert.equal(utf8Bytes(ascii), ascii);
  for (const text of ["", ascii, "Àà你好😀", "\ud800x\udfff", `${ascii}你好\0`])
    assert.deepEqual(octets(utf8Bytes(text)), new TextEncoder().encode(text));
});

test("ASCII case folding preserves every high byte and only changes A through Z", () => {
  const input = String.fromCharCode(...Array.from({ length: 256 }, (_, i) => i));
  const expected = String.fromCharCode(
    ...Array.from({ length: 256 }, (_, i) => (i >= 65 && i <= 90 ? i + 32 : i)),
  );
  assert.equal(asciiLower(input), expected);
});
