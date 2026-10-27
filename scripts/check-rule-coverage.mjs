#!/usr/bin/env node
/** Prevent a single harmless CI probe from masquerading as a deployed rule set. */
import { readFile } from "node:fs/promises";
import { loadPolicy, visit } from "../dist/packages/rule-ir/index.js";
import { validateHeaderPolicy } from "../dist/packages/runtime/header-policy.js";

const path = new URL("../rules/active.json", import.meta.url);
const policy = validateHeaderPolicy(loadPolicy(await readFile(path, "utf8")), "api");
const active = policy.rules.filter((rule) => rule.enabled);
if (active.length < 12) throw new Error("Fewer than 12 executable security rules");
if (active.some((rule) => /(?:^test-|probe-only|pipeline-validation)/i.test(rule.id))) {
  throw new Error("Placeholder-only rules are not an acceptable active policy");
}
const fields = new Map();
for (const rule of active) {
  const found = new Set();
  visit(rule.when, (term) => found.add(term.field));
  for (const field of found) fields.set(field, (fields.get(field) ?? 0) + 1);
}
if ((fields.get("path") ?? 0) < 8 || (fields.get("query") ?? 0) < 2 ||
    (fields.get("header") ?? 0) < 1) {
  throw new Error("Active policy lost its minimum path/query/header coverage");
}
console.log(JSON.stringify({ executableRules: active.length,
  path: fields.get("path") ?? 0, query: fields.get("query") ?? 0,
  header: fields.get("header") ?? 0, upstreamSecLangExecutable: false }));
