#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { compileSecLang, executeSecLang } from "../dist/packages/seclang/index.js";

const body = await readFile(new URL("../rules/native.conf", import.meta.url), "utf8");
const compiled = compileSecLang(body, { strict: true });
if (compiled.supportedRules < 8) throw new Error("Native baseline under-sized");
const cases = [
  ["https://example.test/.env", 403],
  ["https://example.test/.git/config", 403],
  ["https://example.test/wp-config.php", 403],
  ["https://example.test/actuator/env", 403],
  ["https://example.test/api?q=1%20UNION%20SELECT%20email", 403],
  ["https://example.test/api?q=%3Cscript%3E", 403],
  ["https://example.test/api?report=normal", 200],
  ["https://example.test/actuator/health", 200],
  ["https://example.test/.well-known/security.txt", 200],
];
for (const [url, status] of cases) {
  const result = executeSecLang(compiled, { url, method: "GET", headers: {} });
  if (result.status !== status) throw new Error(`Native regression failed: ${url}`);
}
console.log(
  JSON.stringify({
    nativeRules: compiled.supportedRules,
    cases: cases.length,
    convertedToIR: false,
  }),
);
