#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { readFile, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { importInventory } from "../dist/integrations/sbom/index.js";
import { applySources } from "../dist/packages/control-plane/source-apply.js";
import { evaluateComponent, queryOsv } from "../dist/packages/vulnerability/osv.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rules = (name) => join(root, "rules", name);
const parse = async (path) => JSON.parse(await readFile(path, "utf8"));

async function saveIfChanged(path, value) {
  const bytes = JSON.stringify(value, null, 2).concat("\n");
  if (Buffer.byteLength(bytes) > 131072) throw new Error("Report exceeds 128 KiB");
  let old = "";
  try {
    old = await readFile(path, "utf8");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (old === bytes) return false;
  const temporary = [path, randomUUID(), "tmp"].join(".");
  try {
    await writeFile(temporary, bytes, { flag: "wx", mode: 0o600 });
    await rename(temporary, path);
  } finally {
    await unlink(temporary).catch(() => {});
  }
  return true;
}

async function components() {
  const manifest = await parse(join(root, "package.json"));
  const found = [];
  for (const name of Object.keys(manifest.dependencies ?? {})) {
    if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(name)) {
      throw new Error("Invalid dependency name");
    }
    const installed = await parse(join(root, "node_modules", ...name.split("/"), "package.json"));
    if (installed.name !== name || !installed.version) {
      throw new Error("Missing installed dependency version");
    }
    found.push({ name, version: installed.version, ecosystem: "npm" });
  }
  found.push(...importInventory(await parse(rules("inventory.json"))));
  const unique = new Map(
    found.map((item) => [JSON.stringify([item.ecosystem, item.name, item.version]), item]),
  );
  if (unique.size > 50) throw new Error("Inventory exceeds 50 packages");
  return [...unique.values()];
}

async function cveReport() {
  const approved = await parse(rules("emergency-paths.json"));
  if (!approved || Array.isArray(approved) || typeof approved !== "object") {
    throw new Error("Emergency path configuration must be an object");
  }
  const findings = [];
  for (const component of await components()) {
    const advisories = await queryOsv(component);
    for (const advisory of advisories) {
      const exposure = evaluateComponent(advisory, component);
      if (exposure.status === "not-affected") continue;
      const key = [component.ecosystem, component.name].join(":");
      const paths = approved[key] ?? [];
      if (
        !Array.isArray(paths) ||
        paths.length > 20 ||
        paths.some(
          (path) =>
            typeof path !== "string" || !/^\/[A-Za-z0-9_./~-]*$/.test(path) || path.includes(".."),
        )
      ) {
        throw new Error(["Invalid emergency path approval for", key].join(" "));
      }
      const isolation = exposure.status === "affected" ? paths : [];
      findings.push({
        advisory: advisory.id,
        component,
        exposure,
        recommendation: isolation.length
          ? "feature-isolation-candidate"
          : "patch-or-exposure-review",
        preapprovedPaths: isolation,
        maximumTtlSeconds: isolation.length ? 3600 : 0,
        deployed: false,
        reviewRequired: true,
      });
      if (findings.length > 200) throw new Error("Too many CVE findings");
    }
  }
  findings.sort((a, b) =>
    (a.advisory + a.component.name).localeCompare(b.advisory + b.component.name),
  );
  return {
    version: 1,
    purpose: "OSV candidates for installed dependencies and declared origin assets, not deployment",
    deployed: false,
    findings,
  };
}

const policy = await applySources(rules("sources.yaml"));
const cveChanged = await saveIfChanged(rules("cve-candidates.json"), await cveReport());
console.log(
  JSON.stringify({
    rulesUpdated: policy.applied,
    policyVersion: policy.version,
    testsPassed: policy.tests,
    sourceTests: policy.sources,
    cveUpdated: cveChanged,
    productionUpdated: false,
  }),
);
