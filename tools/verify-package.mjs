import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { parseConfigText } from "../tools/.build/scr/config.js";

const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error("Run via npm");
const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const info = JSON.parse(
  execFileSync(process.execPath, [npmCli, "pack", "--dry-run", "--json"], { encoding: "utf8" }),
)[0];
const paths = new Set(info.files.map((f) => f.path));
for (const file of [
  "tools/.build/scr/runtime/index.js",
  "tools/.build/scr/seclang/node.js",
  "tools/.build/scr/seclang/vendor/pcre2.wasm",
  "tools/.build/scr/seclang/vendor/libinjection.wasm",
  "rules/seclang-bundle.json",
  "LICENSE",
])
  if (!paths.has(file)) throw new Error(`Missing package file: ${file}`);
for (const target of Object.values(manifest.exports))
  await access(new URL(`../${target}`, import.meta.url));
const privateKeys = parseConfigText(
  await readFile(new URL("../secret/credentials.yml", import.meta.url), "utf8"),
);
function secretStrings(value) {
  if (typeof value === "string") return value.length >= 32 ? [value] : [];
  if (value && typeof value === "object") return Object.values(value).flatMap(secretStrings);
  return [];
}
for (const file of paths) {
  if (
    /^tools\/(?!\.build\/|sync-native-seclang\.mjs$|verify-full-crs\.mjs$|build-platform\.mjs$|platform-command\.mjs$)|node_modules\/|\.db$|^secret\/(?!(?:credentials|relay-server)\.example\.yml$)/.test(
      file,
    )
  )
    throw new Error(`Unwanted package file: ${file}`);
  const bytes = await readFile(new URL(`../${file}`, import.meta.url));
  for (const value of secretStrings(privateKeys))
    if (bytes.includes(Buffer.from(value)))
      throw new Error(`Private credential found in package: ${file}`);
}
const directory = await mkdtemp(join(tmpdir(), "edgeshield-package-"));
if (!resolve(directory).startsWith(`${resolve(tmpdir()) + sep}edgeshield-package-`))
  throw new Error("Unsafe package verification directory");
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
      "--package-lock=true",
      "--no-audit",
      "--no-fund",
      join(directory, packed.filename),
    ],
    { cwd: directory, stdio: "pipe" },
  );
  const result = execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `import {createRequire} from 'node:module';import{dirname,join}from'node:path';const r=createRequire(import.meta.url);const {compileSecLang,executeSecLang}=await import('@jsw-teams/edgeshield/seclang');const{loadSecLangFile}=await import('@jsw-teams/edgeshield/seclang/node');const root=dirname(dirname(dirname(dirname(dirname(r.resolve('@jsw-teams/edgeshield'))))));const loaded=await loadSecLangFile(join(root,'rules/seclang-bundle.json'));const program=compileSecLang(loaded.secLang,{...loaded.secLangOptions,strict:true});if(program.sourceRules<600||program.unsupported.length)throw Error('Incomplete packaged CRS');const result=executeSecLang(program,{url:'https://test/?q=1%20UNION%20SELECT%20password%20FROM%20users',method:'GET',protocol:'HTTP/1.1',remoteAddr:'192.0.2.1',headers:{host:'test','user-agent':'Mozilla/5.0',accept:'text/html'}});if(!result.blocked||!result.matched.includes('949110'))throw Error('Packaged CRS bypass');program.dispose();console.log('Isolated npm consumer executed complete CRS');`,
    ],
    { cwd: directory, encoding: "utf8" },
  );
  console.log(result.trim());
  const cli = join(directory, "node_modules/@jsw-teams/edgeshield/tools/.build/scr/cli/main.js");
  if (
    execFileSync(process.execPath, [cli, "--version"], {
      cwd: directory,
      encoding: "utf8",
    }).trim() !== manifest.version
  )
    throw new Error("Packaged CLI version mismatch");
  const operator = join(directory, "operator");
  execFileSync(process.execPath, [cli, "init", operator], { cwd: directory, stdio: "pipe" });
  const first = await readFile(join(operator, "secret/credentials.yml"));
  execFileSync(process.execPath, [cli, "init", operator], { cwd: directory, stdio: "pipe" });
  if (!first.equals(await readFile(join(operator, "secret/credentials.yml"))))
    throw new Error("Initialization overwrote operator secrets");
  for (const platform of ["cloudflare", "vercel", "netlify", "esa", "edgeone"]) {
    const built = JSON.parse(
      execFileSync(process.execPath, [cli, "build", platform, join(operator, "config.yml")], {
        cwd: operator,
        encoding: "utf8",
      }),
    );
    await access(join(built.deployDirectory, "package.json"));
    const plan = JSON.parse(
      execFileSync(
        process.execPath,
        [cli, "deploy", platform, join(operator, "config.yml"), "--plan"],
        { cwd: operator, encoding: "utf8" },
      ),
    );
    if (plan.platform !== platform || !plan.args?.length)
      throw Error("Installed platform command failed");
  }
  execFileSync(process.execPath, [cli, "build", "local", join(operator, "config.yml")], {
    cwd: operator,
    stdio: "pipe",
  });
  const config = parseConfigText(await readFile(join(operator, "config.yml"), "utf8"));
  config.listen.port = 0;
  await writeFile(join(operator, "config.yml"), JSON.stringify(config));
  const child = spawn(process.execPath, [cli, "start", "local", join(operator, "config.yml")], {
    cwd: operator,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.resume();
  let stderr = "";
  try {
    const port = await new Promise((done, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`Packaged CLI startup failed: ${stderr}`)),
        15000,
      );
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
        const match = /listening at http:\/\/127\.0\.0\.1:(\d+);/.exec(stderr);
        if (match) {
          clearTimeout(timer);
          done(Number(match[1]));
        }
      });
      child.once("error", reject);
      child.once("exit", () => {
        clearTimeout(timer);
        reject(new Error(`Packaged CLI exited: ${stderr}`));
      });
    });
    const send = (path) =>
      new Promise((done, reject) => {
        const req = httpRequest(
          {
            hostname: "127.0.0.1",
            port,
            path,
            headers: {
              host: "api.example",
              "user-agent": "Mozilla/5.0",
              accept: "application/json",
            },
          },
          (response) => {
            response.resume();
            response.once("end", () => done(response.statusCode));
          },
        );
        req.once("error", reject);
        req.end();
      });
    if (
      (await send("/health")) !== 200 ||
      (await send("/api?q=1%20UNION%20SELECT%20password%20FROM%20users")) !== 403
    )
      throw new Error("Packaged CLI full request flow failed");
  } finally {
    if (child.exitCode === null) {
      const stopped = once(child, "exit");
      child.kill("SIGTERM");
      await stopped;
    }
  }
  console.log(
    "Isolated npm CLI initialized, preserved secrets, served normal traffic and blocked SQLi",
  );
  execFileSync(process.execPath, [npmCli, "audit", "--omit=dev", "--audit-level=moderate"], {
    cwd: directory,
    stdio: "pipe",
  });
  console.log(
    `Package verified: ${paths.size} files; no private credentials; isolated dependency audit passed`,
  );
} finally {
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
