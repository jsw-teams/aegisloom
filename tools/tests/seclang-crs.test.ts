import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { loadSecLangFile } from "../../scr/seclang/node.js";
import { parseSecLangSyntax } from "../../scr/seclang/syntax.js";
import { compileSecLang, executeSecLang } from "./seclang-helpers.js";

test("complete pinned CRS has an instruction for every rule and executes at all paranoia levels", async () => {
  const bundle = JSON.parse(
    await readFile(new URL("../../rules/seclang-bundle.json", import.meta.url), "utf8"),
  );
  const loaded = await loadSecLangFile(
    fileURLToPath(new URL("../../rules/seclang-bundle.json", import.meta.url)),
  );
  const vm = compileSecLang(loaded.secLang, { ...loaded.secLangOptions, strict: true });
  try {
    let expected = 0,
      actual = 0;
    for (const [path, source] of Object.entries(bundle.files))
      if (path.endsWith(".conf"))
        expected += parseSecLangSyntax(source as string).filter((s) =>
          ["SecRule", "SecAction"].includes(s.directive),
        ).length;
    for (const root of vm.instructions)
      if (root.type === "rule") for (let node: any = root; node; node = node.next) actual++;
    assert.equal(actual, expected);
    assert.equal(vm.unsupported.length, 0);
    for (const level of [1, 2, 3, 4]) {
      const send = (q: string) =>
        executeSecLang(
          vm,
          {
            url: `https://example.test/?q=${encodeURIComponent(q)}`,
            method: "GET",
            protocol: "HTTP/1.1",
            remoteAddr: "192.0.2.5",
            headers: { host: "example.test", "user-agent": "Mozilla/5.0", accept: "text/html" },
          },
          { tx: { blocking_paranoia_level: level, detection_paranoia_level: level } },
        );
      assert.equal(send("hello").blocked, false, `Normal traffic PL${level}`);
      for (const value of [
        "1 UNION SELECT password FROM users",
        "<script>alert(1)</script>",
        "../../../../etc/passwd",
        ";cat /etc/passwd",
      ]) {
        const result = send(value);
        assert.equal(result.blocked, true, `Attack bypass at PL${level}: ${value}`);
        assert.ok(result.matched.includes("949110"));
      }
    }
  } finally {
    vm.dispose();
  }
});
