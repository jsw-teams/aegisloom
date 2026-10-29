import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

for (const mode of ["compatible", "breaking", "deprecated"])
  test(`weekly repair ${mode} handling without retaining locks`, async () => {
    const unpatchable = mode === "breaking",
      deprecated = mode === "deprecated";
    const directory = await mkdtemp(join(tmpdir(), "shield-maintenance-test-"));
    const manifest = {
      name: "fixture-project",
      version: "1.0.0",
      scripts: { prepare: "must never execute" },
      dependencies: { "fixture-parent": "^1.0.0" },
    };
    try {
      await writeFile(join(directory, "package.json"), JSON.stringify(manifest));
      const result = execFileSync(
        process.execPath,
        [resolve(".github/actions/dependency-maintenance/repair.mjs")],
        {
          cwd: directory,
          encoding: "utf8",
          windowsHide: true,
          env: {
            ...process.env,
            GITHUB_WORKSPACE: directory,
            MAINTENANCE_DIRECTORY: ".",
            RUNNER_TEMP: join(directory, "tools/.cache"),
            GITHUB_OUTPUT: join(directory, "outputs"),
            npm_execpath: resolve("tools/tests/fixtures/maintenance-npm.cjs"),
            ...(unpatchable ? { TEST_UNPATCHABLE: "true" } : {}),
            ...(deprecated ? { TEST_DEPRECATED: "true" } : {}),
          },
        },
      );
      assert.equal(JSON.parse(result).blocked, unpatchable || deprecated);
      const updated = JSON.parse(await readFile(join(directory, "package.json"), "utf8"));
      assert.deepEqual(updated.scripts, manifest.scripts);
      assert.match(
        await readFile(join(directory, "outputs"), "utf8"),
        new RegExp(
          `manifest-hash=${createHash("sha256").update(JSON.stringify(updated)).digest("hex")}`,
        ),
      );
      if (unpatchable) assert.equal(updated.overrides, undefined);
      else assert.equal(updated.overrides["fixture-leaf"], "^1.0.2");
      await assert.rejects(readFile(join(directory, "package-lock.json")));
      const report = JSON.parse(
        await readFile(join(directory, "tools/.cache/edgeaegis-maintenance/report.json"), "utf8"),
      );
      assert.equal(report.blocked, unpatchable || deprecated);
      assert.equal(report.deprecated.length, deprecated ? 1 : 0);
      assert.equal(report.locksRetained, false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
