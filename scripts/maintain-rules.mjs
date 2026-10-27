#!/usr/bin/env node
// Verified GitHub file maintenance; does not deploy a Worker or alter TLS configuration.
import { readFile, rename, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { applySources } from "../dist/packages/control-plane/source-apply.js";
import { importInventory } from "../dist/integrations/sbom/index.js";
import { queryOsv, evaluateComponent } from "../dist/packages/vulnerability/osv.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rules = (name) => join(root, "rules", name);
const parse = async (path) => JSON.parse(await readFile(path, "utf8"));

async function saveIfChanged(path, value) {
  const bytes = JSON.stringify(value, null, 2) + "\n";
  if (Buffer.byteLength(bytes) > 131072) throw Error("Rule report too large");
  let old = "";
  try { old = await readFile(path, "utf8"); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  if (old === bytes) return false;
  const tmp = path + "." + randomUUID() + ".tmp";
  try {
    await writeFile(tmp, bytes, { flag: "wx", mode: 0o600 });
    await rename(tmp, path);
  } finally { /* On failure, keep last committed data intact. */ }
  return true;
}

async function components() {
  const packageJson = await parse(join(root, "package.json"));
  const found = [];
  for (const name of Object.keys(packageJson.dependencies ?? {})) {
    if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(name)) throw Error("Bad package name");
    const installed = await parse(join(root, "node_modules", ...name.split("/"), "package.json"));
    if (installed.name !== name || !installed.version) throw Error("Missing installed version");
    found.push({ name, version: installed.version, ecosystem: "npm" });
  }
  found.push(...importInventory(await parse(rules("inventory.json"))));
  const map = new Map(found.map((x) => [JSON.stringify([x.ecosystem, x.name, x.version]), x]));
  if (map.size > 50) throw Error("At most 50 installed/inventory components are supported");
  return [...map.values()];
}

async function reportCve() {
  const approved = await parse(rules("emergency-paths.json"));
  if (!approved || typeof approved !== "object" || Array.isArray(approved))
    throw Error("Emergency path map must be an object");
  const findings = [];
  for (const component of await components()) {
    for (const advisory of await queryOsv(component)) {
      const exposure = evaluateComponent(advisory, component);
      if (exposure.status === "not-affected") continue;
      const key = component.ecosystem + ":" + component.name;
      const paths = approved[key] ?? [];
      if (!Array.isArray(paths) || paths.length > 20 ||
        paths.some((p) => typeof p !== "string" ||
          !/^\/[A-Za-z0-9_./~-]*$/.test(p) || p.includes("..")))
        throw Error("Invalid emergency path approval for " + key);
      const isolation = exposure.status === "affected" ? paths : [];
      findings.push({
        advisory: advisory.id, component, exposure,
        recommendation: isolation.length ? "feature-isolation-candidate" : "patch-or-exposure-review",
        preapprovedPaths: isolation,
        maximumTtlSeconds: isolation.length ? 3600 : 0,
        deployed: false, reviewRequired: true,
      });
      if (findings.length > 200) throw Error("Too many CVE findings");
    }
  }
  findings.sort((a, b) =>
    (a.advisory + a.component.name).localeCompare(b.advisory + b.component.name));
  return {
    version: 1,
    purpose: "OSV findings for installed EdgeShield deps and operator-declared origin assets; no automatic mitigation",
    deployed: false, findings,
  };
}

const policy = await applySources(rules("sources.yaml"));
const cveChanged = await saveIfChanged(rules("cve-candidates.json"), await reportCve());
console.log(JSON.stringify({
  rulesUpdated: policy.applied, policyVersion: policy.version,
  testsPassed: policy.tests, sourceTests: policy.sources,
  cveUpdated: cveChanged, productionUpdated: false,
}));
