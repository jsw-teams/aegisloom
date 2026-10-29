import assert from "node:assert/strict";
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
  assert.throws(
    () => serviceUnit("/usr/bin/node", "/srv/app/main.js", "/srv/config\nExecStart=malicious"),
    /Invalid service path/,
  );
});
