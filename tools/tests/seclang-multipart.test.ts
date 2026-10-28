import assert from "node:assert/strict";
import { test } from "node:test";
import { parseBody } from "../../scr/seclang/body.js";

test("multipart recognizes complete delimiter lines and preserves boundary-like file bytes, preamble and epilogue", () => {
  const content = "binary\0\xff\r\n--boundary-not-a-delimiter\r\nmore bytes";
  const text = `preamble\r\n--boundary\r\nContent-Disposition: form-data; name=file; filename="data.bin"\r\n\r\n${content}\r\n--boundary--\r\nepilogue`;
  const result = parseBody(
    "",
    new Headers({ "content-type": "multipart/form-data; boundary=boundary" }),
    "MULTIPART",
    Uint8Array.from(text, (c) => c.charCodeAt(0)),
  );
  assert.deepEqual(result.files, [{ name: "file", filename: "data.bin", size: content.length }]);
  assert.equal(result.args.length, 0);
});
test("multipart accepts LF delimiters and unquoted field parameters while retaining real part headers", () => {
  const text =
    "--boundary\nContent-Disposition: form-data; name=q\nContent-Type: text/plain\n\nattack\n--boundary--\n";
  const result = parseBody(
    text,
    new Headers({ "content-type": "multipart/form-data; boundary=boundary" }),
    "MULTIPART",
  );
  assert.deepEqual(result.args, [["q", "attack"]]);
  assert.equal(result.partHeaders.length, 2);
  assert.throws(
    () =>
      parseBody(
        text.replace("--boundary--", "--boundary-unclosed"),
        new Headers({ "content-type": "multipart/form-data; boundary=boundary" }),
        "MULTIPART",
      ),
    /Malformed/,
  );
});
