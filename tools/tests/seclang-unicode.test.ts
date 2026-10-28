import assert from "node:assert/strict";
import { resolve } from "node:path";
import { test } from "node:test";
import { loadSecLangFile } from "../../scr/seclang/node.js";
import { compileSecLang, executeSecLang } from "./seclang-helpers.js";

test("full CRS detects Unicode best-fit apostrophe SQLi and guillemet XSS through the real libinjection backend", async () => {
  const native = await loadSecLangFile(resolve("rules/seclang-bundle.json")),
    program = compileSecLang(native.secLang, { ...native.secLangOptions, strict: true });
  try {
    for (const [value, id] of [
      ["%u2019%20OR%201%3D1--%20-", "942100"],
      ["%u2019%20or%20%u2019a%u2019%3d%u2019a", "942100"],
      ["%u00abscript%u00bballert(1)%u00ab/script%u00bb", "941100"],
      ["%u2039script%u203aalert(1)%u2039/script%u203a", "941100"],
    ]) {
      const result = executeSecLang(program, {
        url: `https://test/?id=${value}`,
        method: "GET",
        protocol: "HTTP/1.1",
        remoteAddr: "192.0.2.5",
        headers: { host: "test", "user-agent": "Mozilla/5.0", accept: "text/html" },
      });
      assert.equal(result.blocked, true);
      assert.ok(result.matched.includes(id!));
      assert.ok(result.matched.includes("949110"));
    }
  } finally {
    program.dispose();
  }
});
test("SecUnicodeMapFile loads the requested actual table and fails for a missing table or codepage", () => {
  const source =
    'SecUnicodeMapFile custom.mapping 20127\nSecRule ARGS:q "@streq <" "id:48001,deny,t:urlDecodeUni"';
  assert.throws(() => compileSecLang(source, { strict: true }), /Missing Unicode map/);
  const vm = compileSecLang(source, {
    strict: true,
    files: { "custom.mapping": "20127 (US-ASCII)\n00ab:3c\n" },
  });
  try {
    assert.equal(
      executeSecLang(vm, { url: "https://test/?q=%u00ab", method: "GET" }).blocked,
      true,
    );
  } finally {
    vm.dispose();
  }
});
