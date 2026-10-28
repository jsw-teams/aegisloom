/** Extract the upstream PCRE2 binary without executing the npm package's loader. */

import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { parse } from "acorn";

const folder = process.argv[2];
if (!folder) throw new Error("Usage: node tools/vendor-pcre2.mjs <unpacked pcre2-wasm package>");
const pkg = JSON.parse(await readFile(`${folder}/package.json`, "utf8"));
if (pkg.name !== "pcre2-wasm" || pkg.version !== "10.49.2")
  throw new Error("Unexpected PCRE2 source");
const source = await readFile(`${folder}/dist/pcre2.js`, "utf8");
const ast = parse(source, { ecmaVersion: "latest", sourceType: "module" });
let literal;
function visit(node) {
  if (!node || typeof node !== "object") return;
  if (node.type === "FunctionDeclaration" && node.id?.name === "findWasmBinary") {
    literal = node.body.body[0]?.argument?.arguments?.[0]?.value;
    return;
  }
  for (const child of Object.values(node)) {
    if (Array.isArray(child)) child.forEach(visit);
    else if (child && typeof child === "object") visit(child);
  }
}
visit(ast);
if (typeof literal !== "string") throw new Error("Upstream binary literal not found");
const binary = Uint8Array.from(literal, (ch) => {
  const c = ch.charCodeAt(0);
  return (~c >> 8) & c;
});
if (!WebAssembly.validate(binary)) throw new Error("Invalid PCRE2 WebAssembly");
const destination = new URL("../scr/seclang/vendor/", import.meta.url);
await mkdir(destination, { recursive: true });
await writeFile(new URL("pcre2.wasm", destination), binary);
await copyFile(`${folder}/LICENSE`, new URL("PCRE2-WRAPPER-LICENSE", destination));
await copyFile(`${folder}/NOTICE`, new URL("PCRE2-NOTICE", destination));
await writeFile(
  new URL("pcre2.json", destination),
  `${JSON.stringify(
    {
      package: pkg.name,
      version: pkg.version,
      repository: "https://github.com/gudoshnikovn/pcre2-wasm",
      sha256: createHash("sha256").update(binary).digest("hex"),
      bytes: binary.length,
    },
    null,
    2,
  )}\n`,
);
console.log(`Vendored PCRE2: ${binary.length} bytes`);
