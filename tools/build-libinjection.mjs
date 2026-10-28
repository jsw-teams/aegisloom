import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const [compiler, source] = process.argv.slice(2);
if (!compiler || !source)
  throw new Error("Usage: node tools/build-libinjection.mjs <zig> <libinjection source>");
const commit = "5e3f345d4e4793ee5587a9bffe3d7bda95c1611b";
if (
  execFileSync("git", ["-C", source, "rev-parse", "HEAD"], { encoding: "utf8" }).trim() !== commit
)
  throw new Error("Unexpected libinjection source commit");
const directory = new URL("../scr/seclang/vendor/", import.meta.url);
const output = new URL("libinjection.wasm", directory);
execFileSync(
  resolve(compiler),
  [
    "cc",
    "-target",
    "wasm32-wasi",
    "-mexec-model=reactor",
    "-O2",
    "-DNDEBUG",
    ...["sqli", "xss", "html5"].map((part) => resolve(source, "src", `libinjection_${part}.c`)),
    "-Wl,-z,stack-size=1048576",
    "-Wl,--export=malloc",
    "-Wl,--export=free",
    "-Wl,--export=libinjection_sqli",
    "-Wl,--export=libinjection_xss",
    "-Wl,--max-memory=16777216",
    "-o",
    fileURLToPath(output),
  ],
  { stdio: "inherit" },
);
const binary = await readFile(output);
await copyFile(resolve(source, "COPYING"), new URL("LIBINJECTION-LICENSE", directory));
await writeFile(
  new URL("libinjection.json", directory),
  `${JSON.stringify(
    {
      repository: "https://github.com/libinjection/libinjection",
      commit,
      compiler: `Zig ${execFileSync(resolve(compiler), ["version"], { encoding: "utf8" }).trim()}`,
      bytes: binary.length,
      sha256: createHash("sha256").update(binary).digest("hex"),
    },
    null,
    2,
  )}\n`,
);
const module = await WebAssembly.compile(binary);
if (WebAssembly.Module.imports(module).length)
  throw new Error("Libinjection has unexpected host imports");
console.log(`Built libinjection: ${binary.length} bytes; no host imports`);
