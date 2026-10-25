import { readFile, writeFile } from "node:fs/promises";

const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
if (!/^[1-9][0-9]{3}\.(?:[1-9]|1[0-2])\.[1-9][0-9]*$/.test(manifest.version))
  throw new Error("Use YYYY.M.N (year, month, release ordinal); published versions are immutable");
const target = new URL("../packages/core/version.ts", import.meta.url);
const code = `// Generated from package.json by scripts/sync-version.mjs.\nexport const SHIELD_VERSION = "${manifest.version}";\n`;
if (process.argv.includes("--check")) {
  if ((await readFile(target, "utf8")) !== code)
    throw new Error("CLI version is stale; run npm run version");
} else await writeFile(target, code);
