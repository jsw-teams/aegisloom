import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { serviceUnit } from "../../scr/cli/service.js";

test("SSH service command preserves literal paths without shell or systemd expansion and rejects injected directives", () => {
  const unit = serviceUnit(
    "/usr/bin/node",
    "/srv/my app/100%/$bin/main.js",
    "/srv/my app/config.yml",
  );
  assert.match(
    unit,
    /ExecStart="\/usr\/bin\/node" "\/srv\/my app\/100%%\/\$\$bin\/main.js" serve "\/srv\/my app\/config.yml"/,
  );
  assert.match(unit, /Restart=on-failure/);
  assert.match(unit, /StandardError=journal/);
  assert.match(unit, /NoNewPrivileges=true/);
  assert.match(unit, /WorkingDirectory=\/srv\/my app\n/);
  assert.throws(
    () => serviceUnit("/usr/bin/node", "/srv/app/main.js", "/srv/config\nExecStart=malicious"),
    /Invalid service path/,
  );
});
if (process.platform === "linux")
  test("generated background unit passes real systemd validation with a space in its working directory", async () => {
    const directory = await mkdtemp(join(tmpdir(), "edgeaegis service-"));
    try {
      const file = join(directory, "edgeaegis-verify.service");
      await writeFile(
        file,
        serviceUnit(process.execPath, join(directory, "main.js"), join(directory, "config.yml")),
      );
      execFileSync("systemd-analyze", ["verify", file], { stdio: "pipe", windowsHide: true });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
