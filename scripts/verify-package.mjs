import { execFileSync } from "node:child_process";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";

const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error("Run using npm run verify:package");
const info = JSON.parse(
  execFileSync(process.execPath, [npmCli, "pack", "--dry-run", "--json"], { encoding: "utf8" }),
)[0];
const paths = new Set(info.files.map((f) => f.path));
for (const path of [
  "dist/packages/cli/main.js",
  "dist/packages/rule-ir/schema.json",
  "dist/packages/rule-ir/validator.js",
  "dist/packages/runtime/index.js",
  "dist/packages/backend-security/index.js",
  "dist/packages/protocols/index.js",
  "dist/integrations/rule-converter/sources.js",
  "dist/integrations/rule-converter/sources.schema.json",
  "dist/adapters/cloudflare/runtime.js",
  "dist/adapters/vercel/index.js",
  "LICENSE",
])
  if (!paths.has(path)) throw new Error(`Missing package file: ${path}`);
for (const path of paths)
  if (/^(tests|examples|api-shield-convert|node_modules)\//.test(path) || /\.env$|\.db$/.test(path))
    throw new Error(`Unwanted package file: ${path}`);
const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url)));
for (const target of Object.values(manifest.exports))
  await access(new URL(`../${target}`, import.meta.url));
const { loadPolicy } = await import("../dist/packages/rule-ir/index.js");
const { createShield } = await import("../dist/packages/runtime/index.js");
const { MemoryDecisionStore } = await import("../dist/packages/decision-cache/index.js");
const engine = await createShield({
  tenant: "test",
  service: "api",
  publicHosts: ["package.test"],
  routes: [],
  policy: loadPolicy({ version: "1", rules: [] }),
  decisions: new MemoryDecisionStore(),
  proxy: {
    origin: "https://origin.invalid",
    allowedOrigins: ["https://origin.invalid"],
    originToken: "package-verification-token-never-sent",
    fetch: async () => {
      throw new Error("Unexpected network");
    },
  },
});
if ((await engine.handle(new Request("https://package.test/"), { tenant: "test" })).status !== 404)
  throw new Error("Built artifact failed smoke test");
console.log(`Package verified: ${paths.size} files; built ESM imports and rejection path work.`);
const directory = await mkdtemp(join(tmpdir(), "shield-package-"));
if (!resolve(directory).startsWith(`${resolve(tmpdir())}${sep}shield-package-`))
  throw new Error("Refusing unsafe temporary package path");
try {
  const packed = JSON.parse(
    execFileSync(process.execPath, [npmCli, "pack", "--json", "--pack-destination", directory], {
      encoding: "utf8",
    }),
  )[0];
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  execFileSync(
    process.execPath,
    [
      npmCli,
      "install",
      "--ignore-scripts",
      "--no-fund",
      "--no-audit",
      join(directory, packed.filename),
    ],
    { cwd: directory, stdio: "pipe" },
  );
  const consumer = execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      "const r=await import('@cloud-api-shield/shield/rules'); const p=r.loadPolicy({version:'1',rules:[]}); const e=await import('@cloud-api-shield/shield'); const b=await import('@cloud-api-shield/shield/http-boundary'); const s=await import('@cloud-api-shield/shield/sources'); s.validateSources({version:'1',upstreams:[],ruleSources:[],permittedLicenses:['Apache-2.0']}); if(p.version!=='1'||typeof e.createShield!=='function'||typeof b.checkBoundary!=='function'||typeof b.parseStrictJson!=='function')throw Error('bad exports'); console.log('isolated tarball ESM imports passed');",
    ],
    { cwd: directory, encoding: "utf8" },
  );
  execFileSync(process.execPath, [npmCli, "audit", "--omit=dev", "--audit-level=moderate"], {
    cwd: directory,
    stdio: "pipe",
  });
  console.log(consumer.trim());
  console.log(
    "Isolated consumer dependency audit passed; package-manager overrides were not inherited.",
  );
} finally {
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
