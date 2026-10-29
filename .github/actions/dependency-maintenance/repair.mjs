import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";

const workspace = realpathSync(process.env.GITHUB_WORKSPACE || process.cwd());
const directory = realpathSync(resolve(workspace, process.env.MAINTENANCE_DIRECTORY || "."));
if (directory !== workspace && !directory.startsWith(workspace + sep))
  throw new Error("Maintenance directory escaped checkout");
const level = process.env.AUDIT_LEVEL || "moderate",
  severity = ["info", "low", "moderate", "high", "critical"];
if (!severity.includes(level)) throw new Error("Invalid audit threshold");
const npmCli = process.env.npm_execpath || realpathSync(join(dirname(process.execPath), "npm"));
const semver = createRequire(npmCli)("semver");
const original = JSON.parse(await readFile(join(directory, "package.json"), "utf8"));
const proposed = structuredClone(original),
  report = { updated: [], blocked: [], remaining: [] };
const temporary = await mkdtemp(join(tmpdir(), "edgeaegis-repair-"));
if (!resolve(temporary).startsWith(resolve(tmpdir()) + sep + "edgeaegis-repair-"))
  throw new Error("Invalid temporary directory");
const environment = {
  ...process.env,
  GIT_CONFIG_COUNT: "1",
  GIT_CONFIG_KEY_0: "url.https://github.com/.insteadOf",
  GIT_CONFIG_VALUE_0: "ssh://git@github.com/",
};
function npm(args, allowFailure = false) {
  try {
    return execFileSync(process.execPath, [npmCli, ...args], {
      cwd: temporary,
      env: environment,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 300000,
      maxBuffer: 8 * 1024 * 1024,
    });
  } catch (error) {
    if (allowFailure && error.stdout) return String(error.stdout);
    throw new Error("Dependency metadata/resolution command failed");
  }
}
const cache = new Map();
function versions(name) {
  if (!/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(name))
    throw new Error("Invalid package name");
  if (!cache.has(name)) {
    const data = JSON.parse(npm(["view", name, "versions", "--json"]));
    cache.set(
      name,
      (Array.isArray(data) ? data : [data]).filter(
        (v) => typeof v === "string" && semver.valid(v) && !semver.prerelease(v),
      ),
    );
  }
  return cache.get(name);
}
async function resolveTree() {
  const snapshot = { name: original.name, version: original.version, private: true };
  for (const key of ["dependencies", "devDependencies", "optionalDependencies", "overrides"])
    if (proposed[key]) snapshot[key] = structuredClone(proposed[key]);
  for (const group of ["dependencies", "devDependencies", "optionalDependencies"])
    for (const [name, spec] of Object.entries(snapshot[group] || {}))
      if (typeof spec === "string" && spec.startsWith("file:"))
        snapshot[group][name] = `file:${resolve(directory, spec.slice(5))}`;
  await writeFile(join(temporary, "package.json"), JSON.stringify(snapshot));
  npm([
    "install",
    "--package-lock-only",
    "--package-lock=true",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
  ]);
  const audit = JSON.parse(npm(["audit", "--package-lock-only", "--json"], true));
  if (!audit.metadata || !audit.vulnerabilities)
    throw new Error("Invalid dependency audit response");
  return { audit, lock: JSON.parse(await readFile(join(temporary, "package-lock.json"), "utf8")) };
}
function updateOverride(object, name, value) {
  let found = false;
  for (const [key, current] of Object.entries(object)) {
    if (key === name && typeof current === "string") {
      object[key] = value;
      found = true;
    } else if (current && typeof current === "object")
      found = updateOverride(current, name, value) || found;
  }
  return found;
}
try {
  for (const group of ["dependencies", "devDependencies", "optionalDependencies"])
    for (const [name, range] of Object.entries(proposed[group] || {})) {
      // Explicit URLs, Git ranges, prereleases and arbitrary operators retain their operator intent.
      if (typeof range !== "string" || !/^([~^])\d+\.\d+\.\d+$/.test(range)) continue;
      const wanted = semver.maxSatisfying(versions(name), range),
        minimum = semver.minVersion(range);
      if (wanted && minimum && semver.gt(wanted, minimum)) {
        proposed[group][name] = range[0] + wanted;
        report.updated.push({ name, from: range, to: proposed[group][name] });
      }
    }
  let tree = await resolveTree();
  // Exact transitive pins may require a same-major override even after fresh resolution.
  for (const [name, vulnerability] of Object.entries(tree.audit.vulnerabilities)) {
    const advisories = vulnerability.via.filter((v) => typeof v === "object" && v.range);
    if (!advisories.length || severity.indexOf(vulnerability.severity) < severity.indexOf(level))
      continue;
    const installed = vulnerability.nodes
      .map((path) => tree.lock.packages?.[path]?.version)
      .filter((v) => semver.valid(v));
    if (!installed.length || new Set(installed.map((v) => semver.major(v))).size !== 1) {
      report.blocked.push({ name, reason: "multiple-or-unknown-major-versions" });
      continue;
    }
    const major = semver.major(installed[0]);
    const safe = versions(name).filter(
      (v) =>
        semver.major(v) === major &&
        installed.every((old) => semver.gte(v, old) && semver.satisfies(v, `^${old}`)) &&
        advisories.every((a) => !semver.satisfies(v, a.range)),
    );
    const target = semver.rsort(safe)[0];
    if (!target) {
      report.blocked.push({ name, reason: "no-compatible-patched-version" });
      continue;
    }
    const direct = ["dependencies", "devDependencies", "optionalDependencies"].find(
      (group) => proposed[group]?.[name],
    );
    if (direct) {
      if (
        !semver.validRange(proposed[direct][name]) ||
        !semver.satisfies(target, proposed[direct][name])
      ) {
        report.blocked.push({ name, reason: "outside-approved-direct-range" });
        continue;
      }
      proposed[direct][name] = "^" + target;
    } else {
      proposed.overrides ??= {};
      if (!updateOverride(proposed.overrides, name, "^" + target))
        proposed.overrides[name] = "^" + target;
    }
    report.updated.push({ name, to: "^" + target, reason: "same-major-security-fix" });
  }
  tree = await resolveTree();
  report.deprecated = Object.entries(tree.lock.packages ?? {})
    .filter(([,pkg]) => typeof pkg.deprecated === "string" && pkg.deprecated)
    .map(([path,pkg]) => ({path,version:pkg.version,message:pkg.deprecated}));
  report.remaining = Object.entries(tree.audit.vulnerabilities)
    .filter(([, v]) => severity.indexOf(v.severity) >= severity.indexOf(level))
    .map(([name, v]) => ({ name, severity: v.severity }));
  const changed = JSON.stringify(original) !== JSON.stringify(proposed),
    blocked = report.remaining.length > 0 || report.deprecated.length > 0;
  const artifact = resolve(process.env.RUNNER_TEMP || tmpdir(), "edgeaegis-maintenance");
  await mkdir(artifact, { recursive: true });
  await writeFile(join(artifact, "package.json"), JSON.stringify(proposed, null, 2) + "\n");
  await writeFile(
    join(artifact, "report.json"),
    JSON.stringify({ ...report, changed, blocked, locksRetained: false }, null, 2) + "\n",
  );
  if (changed)
    await writeFile(join(directory, "package.json"), JSON.stringify(proposed, null, 2) + "\n");
  if (process.env.GITHUB_OUTPUT)
    await appendFile(
      process.env.GITHUB_OUTPUT,
      `changed=${changed}\nblocked=${blocked}\nmanifest-hash=${createHash("sha256").update(JSON.stringify(proposed)).digest("hex")}\n`,
    );
  console.log(
    JSON.stringify({
      changed,
      blocked,
      compatibleUpdates: report.updated.length,
      remaining: report.remaining,
      deprecated: report.deprecated,
    }),
  );
} finally {
  await rm(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
