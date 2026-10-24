import assert from "node:assert/strict";
import { resolve } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { importConversion } from "../integrations/rule-converter/index.js";
import { compileExpression } from "../packages/core/matcher.js";
import { context, request } from "./helpers.js";

test("independently packaged converter output validates against main IR and retains method semantics", async () => {
  const { convert } = await import(pathToFileURL(resolve("api-shield-convert/src/index.mjs")).href);
  const source =
    'SecRule REQUEST_METHOD "@streq DELETE" "id:100,phase:1,deny,t:none,msg:\'Block DELETE\'"';
  const report = convert(source, {
    format: "seclang",
    url: "operator:test",
    version: "1",
    license: "Apache-2.0",
    service: "api",
  });
  const original = new TextEncoder().encode(source);
  const policy = await importConversion(report, original, ["Apache-2.0"]);
  const match = compileExpression(policy.rules[0]!.when);
  for (const method of ["GET", "POST", "DELETE", "PATCH"]) {
    const req = request("", { method });
    assert.equal(
      match({ request: req, url: new URL(req.url), path: "/api", bodyText: "", context }),
      method === "DELETE",
    );
  }
  await assert.rejects(importConversion(report, original, ["MIT"]), /license/);
  await assert.rejects(
    importConversion(report, new TextEncoder().encode("modified"), ["Apache-2.0"]),
    /checksum/,
  );
  await assert.rejects(
    importConversion({ ...report, status: "partial" }, original, ["Apache-2.0"]),
    /Lossy/,
  );
  const tampered = structuredClone(report);
  tampered.policy.rules[0].provenance.version = "different";
  await assert.rejects(importConversion(tampered, original, ["Apache-2.0"]), /provenance/);
});
