import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";

const sourceBlob = "2654c4a619bd585de547d0e4eeecec5753d56eeb";
const payload = JSON.parse(
  execFileSync("gh", ["api", `repos/owasp-modsecurity/ModSecurity/git/blobs/${sourceBlob}`], {
    encoding: "utf8",
    windowsHide: true,
  }),
);
const bytes = Buffer.from(payload.content, "base64");
if (createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex") !== sourceBlob)
  throw new Error("Unicode mapping Git blob mismatch");
const lines = bytes.toString("utf8").split(/\r?\n/),
  start = lines.findIndex((line) => /^20127\s/.test(line));
if (start < 0) throw new Error("US-ASCII mapping missing");
const mapping = {};
for (let i = start + 1; i < lines.length; i++) {
  if (/^\d+\s/.test(lines[i])) break;
  for (const match of lines[i].matchAll(/\b([a-f\d]{4}):([a-f\d]{2})\b/gi))
    mapping[Number.parseInt(match[1], 16)] = Number.parseInt(match[2], 16);
}
if (Object.keys(mapping).length < 100 || mapping[0x2019] !== 39 || mapping[0xab] !== 60)
  throw new Error("Unicode mapping validation failed");
await writeFile(
  new URL("../scr/seclang/vendor/unicode.json", import.meta.url),
  `${JSON.stringify(
    {
      source: "owasp-modsecurity/ModSecurity/unicode.mapping",
      sourceBlob,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      codepage: 20127,
      mapping,
    },
    null,
    2,
  )}\n`,
);
console.log(JSON.stringify({ sourceBlob, codepage: 20127, entries: Object.keys(mapping).length }));
