import { readFileSync, writeFileSync } from "node:fs";
import { stringify } from "yaml";
import corpus from "./catalog-corpus.json" with { type: "json" };

const samples = [
  ...corpus.attacks.map((id) => ({
    name: id,
    kind: "attack",
    url: `https://simulation.test/api/items?id=${encodeURIComponent(id)}`,
    expectedStatus: 403,
  })),
  ...corpus.legitimate.map((id) => ({
    name: id,
    kind: "legitimate",
    url: `https://simulation.test/api/items?id=${id}`,
    expectedStatus: 204,
  })),
];
writeFileSync("regression.json", JSON.stringify(samples));
writeFileSync("baseline.json", JSON.stringify({ version: "1", rules: [] }));

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
  license: "Apache-2.0",
  service: "api",
});
writeFileSync(
  "sources.yaml",
  stringify({
    version: "1",
    permittedLicenses: ["Apache-2.0"],
    application: {
      policyFile: "auto-policy.json",
      baselineFile: "baseline.json",
      regressionFile: "regression.json",
      service: "api",
    },
    upstreams: [
      profile("cloud-api", "cloud", "https://cloud-origin.example"),
      profile("third-party-vps", "vps", "https://vps-origin.example"),
      profile("isolated-tls-lab", "vps", origin),
    ],
    ruleSources: [
      {
        ...source("native", "rules.yaml", "shield-ir"),
        location: `${origin}/rules.yaml`,
        autoApply: true,
        regressionFile: "regression.json",
      },
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
      policyFile: "auto-policy.json",
      upstream: { file: "sources.yaml", id: "isolated-tls-lab" },
      listen: { host: "127.0.0.1", port: 0 },
      decisions: { kind: "sqlite", path: "state.db" },
    }),
  );
