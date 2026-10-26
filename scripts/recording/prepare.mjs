import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { stringify } from "yaml";

mkdirSync("tls", { recursive: true });
execFileSync(
  "openssl",
  [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "2",
    "-keyout",
    "tls/key.pem",
    "-out",
    "tls/cert.pem",
    "-subj",
    "/CN=ShieldWeave isolated acceptance",
    "-addext",
    "subjectAltName=IP:127.0.0.1",
  ],
  { stdio: "pipe" },
);
const secrets = ["SHIELD_ORIGIN_TOKEN", "SHIELD_ADMIN_TOKEN", "SHIELD_RUNTIME_TOKEN"].map(
  (k) => `${k}=${randomBytes(32).toString("hex")}`,
);
secrets.push(`NODE_EXTRA_CA_CERTS=${resolve("tls/cert.pem")}`);
writeFileSync("private.env", `${secrets.map((line) => `export ${line}`).join("\n")}\n`, {
  mode: 0o600,
});
const policy = {
  version: "1",
  rules: [
    {
      id: "sql-token",
      name: "SQL token guard for isolated acceptance",
      service: "api",
      priority: 10,
      when: {
        field: "query",
        key: "id",
        op: "contains",
        value: "' or ",
        transforms: ["lowercase"],
      },
      then: { action: "block" },
      cache: { enabled: true, ttl: "5m" },
      community: { report: false },
    },
  ],
};
writeFileSync("rules.yaml", stringify(policy));
writeFileSync(
  "method.conf",
  `# Authored acceptance rule, Apache-2.0. This is not a full CRS rule set.\nSecRule REQUEST_METHOD "@streq DELETE" "id:900001,phase:1,deny,t:none,msg:'Temporarily restrict DELETE'"\n`,
);
writeFileSync(
  "unsupported.conf",
  `SecRule REQUEST_URI "@rx attack" "id:900002,phase:2,chain,deny"\nSecRule ARGS "@rx payload" "t:none"\n`,
);
writeFileSync("origin-hits.json", '{"hits":0}');
// Inventory is finished once the real TLS origin has reported its OS-assigned port.
if (process.argv.includes("--inventory"))
  throw new Error("Run configure.mjs after the origin starts");
