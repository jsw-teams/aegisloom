import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";

const workspace = process.env.GITHUB_WORKSPACE,
  directory = resolve(workspace, process.env.MAINTENANCE_DIRECTORY || ".");
if (directory !== workspace && !directory.startsWith(workspace + sep))
  throw new Error("Invalid publish directory");
const path = relative(workspace, resolve(directory, "package.json")).replaceAll("\\", "/");
const base = process.env.MAINTENANCE_BASE_SHA;
if (!/^[a-f0-9]{40}$/.test(base || "")) throw new Error("Invalid tested source revision");
const git = (args, env = process.env) =>
  execFileSync("git", args, {
    cwd: workspace,
    env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 60000,
  });
const original = JSON.parse(git(["show", `${base}:${path}`]));
const proposed = JSON.parse(
  await readFile(resolve(process.env.RUNNER_TEMP, "edgeaegis-maintenance/package.json"), "utf8"),
);
for (const key of new Set([...Object.keys(original), ...Object.keys(proposed)]))
  if (!["dependencies", "devDependencies", "optionalDependencies", "overrides"].includes(key))
    assert.deepEqual(proposed[key], original[key], `Unapproved maintenance field: ${key}`);
git(["checkout", "--detach", base]);
await writeFile(resolve(directory, "package.json"), JSON.stringify(proposed, null, 2) + "\n");
git(["add", "--", path]);
git(["diff", "--cached", "--check"]);
git([
  "-c",
  "user.name=github-actions[bot]",
  "-c",
  "user.email=41898282+github-actions[bot]@users.noreply.github.com",
  "commit",
  "-m",
  "fix(deps): update compatible dependency requirements",
]);
const token = process.env.GH_TOKEN;
if (!token) throw new Error("Missing publishing credential");
const env = {
  ...process.env,
  GIT_CONFIG_COUNT: "1",
  GIT_CONFIG_KEY_0: "http.https://github.com/.extraheader",
  GIT_CONFIG_VALUE_0:
    "AUTHORIZATION: basic " + Buffer.from("x-access-token:" + token).toString("base64"),
};
const branch = process.env.MAINTENANCE_DEFAULT_BRANCH;
if (!branch || !/^\d+$/.test(process.env.GITHUB_RUN_ID || ""))
  throw new Error("Invalid publishing context");
if (process.env.MAINTENANCE_VERIFIED === "true") {
  try {
    git(["push", "origin", `HEAD:refs/heads/${branch}`], env);
    console.log("Verified compatible repair pushed to the default branch.");
    process.exit(0);
  } catch {
    console.log("Default-branch policy or concurrent update requires a repair PR.");
  }
}
const head = `automation/dependency-repair-${process.env.GITHUB_RUN_ID}`;
git(["push", "origin", `HEAD:refs/heads/${head}`], env);
const body = resolve(process.env.RUNNER_TEMP, "dependency-repair-pr.md");
await writeFile(
  body,
  `Compatible dependency repair candidate.\n\nAutomatic application was withheld because checks failed, unresolved findings remain, the branch is protected, or the branch advanced. Review the workflow report before merging. No lockfiles or application code changed.\n\nValidation: https://github.com/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}\n`,
);
execFileSync(
  "gh",
  [
    "pr",
    "create",
    "--base",
    branch,
    "--head",
    head,
    "--title",
    "fix(deps): review compatible dependency repairs",
    "--body-file",
    body,
  ],
  { cwd: workspace, env: process.env, stdio: "inherit", timeout: 60000 },
);
