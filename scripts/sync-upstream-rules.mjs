#!/usr/bin/env node
/** Archive official OWASP CRS in Git. SecLang files are NOT EdgeShield executable policy. */
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const destination = join(root, "rules", "upstream", "crs");
const files = [
  "REQUEST-913-SCANNER-DETECTION.conf",
  "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
  "REQUEST-921-PROTOCOL-ATTACK.conf",
  "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
  "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
  "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
  "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
];
const limit = 131072;
async function download(url, maxSize = limit) {
  const response = await fetch(url, {
    redirect: "error",
    signal: AbortSignal.timeout(15000),
    headers: { accept: "text/plain, application/json", "accept-encoding": "identity" },
  });
  if (response.status !== 200 || !response.body ||
      ![null, "identity"].includes(response.headers.get("content-encoding"))) {
    throw new Error("Unexpected upstream response");
  }
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxSize) throw new Error("Upstream file exceeds size limit");
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  }
  const output = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}
async function save(name, content) {
  const path = join(destination, name);
  const bytes = typeof content === "string" ? Buffer.from(content, "utf8") : content;
  let prior;
  try {
    prior = await readFile(path);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (prior?.equals(bytes)) return false;
  const temp = [path, randomUUID(), "tmp"].join(".");
  try {
    await writeFile(temp, bytes, { flag: "wx", mode: 0o600 });
    await rename(temp, path);
  } finally {
    await unlink(temp).catch(() => {});
  }
  return true;
}
const info = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(
  await download("https://api.github.com/repos/coreruleset/coreruleset/releases/latest", 65536),
));
if (!/^v4\.[0-9]{1,3}\.[0-9]{1,3}$/.test(info.tag_name)) {
  throw new Error("Unexpected OWASP CRS release tag: manual review required");
}
const tag = info.tag_name;
const filesRead = [];
let count = 0;
const candidate = new Map();
for (const name of files) {
  const url = new URL(
    ["https://raw.githubusercontent.com/coreruleset/coreruleset",tag,"rules",name].join("/"),
  );
  const bytes = await download(url.toString());
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const ids = text.match(/\bid:[0-9]{6}\b/g) ?? [];
  if (!text.includes("SecRule") || ids.length < 3) throw new Error("Unrecognized CRS rule file");
  count += ids.length;
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  filesRead.push({ name, bytes: bytes.length, sha256, ruleIds: ids.length });
  candidate.set(name, bytes);
}
if (count < 100) throw new Error("Too few official CRS rules were downloaded");
const license = await download(
  ["https://raw.githubusercontent.com/coreruleset/coreruleset",tag,"LICENSE"].join("/"),
  65536,
);
if (!new TextDecoder().decode(license).includes("Apache License")) {
  throw new Error("Official license text missing");
}
candidate.set("LICENSE", license);
const manifest = {
  project: "OWASP CRS",
  repository: "https://github.com/coreruleset/coreruleset",
  releaseTag: tag,
  license: "Apache-2.0",
  format: "modsecurity-seclang",
  executableByEdgeShield: false,
  policyImportStatus: "awaiting-conversion-and-full-regression",
  provenance: "official release-tag archive, individual file hashes",
  files: filesRead,
};
await mkdir(destination, { recursive: true });
for (const [name, bytes] of candidate) await save(name, bytes);
await save("manifest.json", JSON.stringify(manifest, null, 2).concat("\n"));
console.log(JSON.stringify({ upstream: tag, archivedFiles: filesRead.length, ruleIds: count,
  deployed: false, verifiedBy: "source-format-and-integrity-only" }));
