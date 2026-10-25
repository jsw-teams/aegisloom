import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { stringify } from "yaml";

const origin = readFileSync("origin-url.txt", "utf8").trim();
const profile = (id, kind, url) => ({
  id,
  kind,
  origin: url,
  originTokenEnv: "SHIELD_ORIGIN_TOKEN",
  timeoutMs: 10000,
  maxResponseBytes: 16777216,
});
const source = (id, location, format) => ({
  id,
  enabled: true,
  location,
  format,
  version: "lab-1",
  sha256: createHash("sha256").update(readFileSync(location)).digest("hex"),
  license: "Apache-2.0",
  service: "api",
});
writeFileSync(
  "sources.yaml",
  stringify({
    version: "1",
    permittedLicenses: ["Apache-2.0"],
    upstreams: [
      profile("cloud-api", "cloud", "https://cloud-origin.example"),
      profile("third-party-vps", "vps", "https://vps-origin.example"),
      profile("isolated-tls-lab", "vps", origin),
    ],
    ruleSources: [
      { ...source("native", "rules.yaml", "shield-ir"), location: `${origin}/rules.yaml` },
      source("method", "method.conf", "seclang"),
      source("unsupported", "unsupported.conf", "seclang"),
    ],
  }),
);
for (const id of ["a", "b"])
  writeFileSync(
    `${id}.yaml`,
    stringify({
      tenant: "recording",
      service: "api",
      publicHosts: ["api.vm.test"],
      routes: [{ path: "/api/items", methods: ["GET", "DELETE"], authenticated: false }],
      policyFile: "candidate.json",
      upstream: { file: "sources.yaml", id: "isolated-tls-lab" },
      listen: { host: "127.0.0.1", port: 0 },
      decisions: { kind: "sqlite", path: "state.db" },
    }),
  );
