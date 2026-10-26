import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";

const level = process.env.AUDIT_LEVEL || process.argv[2] || "high";
if (!["info", "low", "moderate", "high", "critical"].includes(level))
  throw new Error("Invalid audit level");
const manifest = JSON.parse(await readFile("package.json", "utf8"));
const directory = await mkdtemp(join(tmpdir(), "dependency-audit-"));
if (!resolve(directory).startsWith(`${resolve(tmpdir())}${sep}dependency-audit-`))
  throw new Error("Invalid audit directory");
const npm = process.env.npm_execpath;
if (!npm) throw new Error("Run this audit using npm run audit");
try {
  const snapshot = { name: manifest.name, version: manifest.version, private: true };
  for (const key of ["dependencies", "devDependencies", "optionalDependencies", "overrides"])
    if (manifest[key]) snapshot[key] = manifest[key];
  await writeFile(join(directory, "package.json"), JSON.stringify(snapshot));
  execFileSync(
    process.execPath,
    [
      npm,
      "install",
      "--package-lock-only",
      "--package-lock=true",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
    ],
    { cwd: directory, stdio: "pipe" },
  );
  execFileSync(
    process.execPath,
    [
      npm,
      "audit",
      "--package-lock-only",
      `--audit-level=${level}`,
      ...(process.argv.includes("--json") ? ["--json"] : []),
    ],
    { cwd: directory, stdio: "inherit" },
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}
