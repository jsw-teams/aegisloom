/** Isolated Linux VM lab. Certificates and keys are generated locally, never operator data. */

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";

const directory = resolve(process.argv[2]),
  archive = resolve(process.argv[3]);
const { stringify } = createRequire(resolve(directory, "package.json"))("yaml");
const credentials = {
  originKeys: Object.fromEntries(
    ["app", "shop", "vps", "balance", "external"].map((name) => [
      name,
      randomBytes(32).toString("base64url"),
    ]),
  ),
};
for (const file of ["403.html", "403.json"])
  await copyFile(
    new URL(`../../respond/${file}`, import.meta.url),
    resolve(directory, "respond", file),
  );
await writeFile(resolve(directory, "secret/credentials.yml"), stringify(credentials), {
  mode: 0o600,
});
const routes = [
  { pattern: "demo.test/app", origin: "function:app" },
  { pattern: "demo.test/shop", origin: "function:shop" },
  { pattern: "demo.test/vps", origin: "https://127.0.0.1:9443", key: "vps" },
  { pattern: "demo.test/balance", origin: "https://lb.demo.test:9444", key: "balance" },
  { pattern: "demo.test/external", origin: "https://function.demo.test:9445", key: "external" },
];
await writeFile(resolve(directory, "origin/config.yml"), stringify({ routes }));
for (const name of ["app", "shop"]) {
  await mkdir(resolve(directory, "origin/cloudflare", name), { recursive: true });
  await writeFile(
    resolve(directory, "origin/cloudflare", name, "index.js"),
    `export default {fetch(){return Response.json({business:${JSON.stringify(name)}});}};`,
  );
}
let policy = await readFile(resolve(directory, "rules/setup.conf"), "utf8");
policy = policy.replaceAll(
  "expirevar:ip.edgeshield_blocked=300",
  "expirevar:ip.edgeshield_blocked=5",
);
await writeFile(resolve(directory, "rules/setup.conf"), policy);
await mkdir(resolve(directory, "tools/lab"), { recursive: true });
execFileSync(
  "openssl",
  [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-keyout",
    resolve(directory, "tools/lab/key.pem"),
    "-out",
    resolve(directory, "tools/lab/cert.pem"),
    "-subj",
    "/CN=EdgeAegis isolated demo",
    "-addext",
    "subjectAltName=IP:127.0.0.1,DNS:lb.demo.test,DNS:function.demo.test",
  ],
  { stdio: "ignore" },
);
await copyFile(
  resolve(directory, "tools/lab/cert.pem"),
  "/usr/local/share/ca-certificates/edgeaegis-demo.crt",
);
execFileSync("update-ca-certificates", [], { stdio: "ignore" });
const hosts = await readFile("/etc/hosts", "utf8");
if (!hosts.includes("lb.demo.test"))
  await writeFile(
    "/etc/hosts",
    `${hosts}\n127.0.0.1 lb.demo.test function.demo.test # edgeaegis-demo\n`,
  );
await copyFile(
  new URL("./tls-origins.mjs", import.meta.url),
  resolve(directory, "tools/lab/origins.mjs"),
);
await writeFile(resolve(directory, "tools/origin-requests.log"), "");
const p = JSON.parse(await readFile(resolve(directory, "package.json"), "utf8"));
p.dependencies.edgeaegis = `file:${archive}`;
p.scripts["deploy:local"] =
  "node --use-system-ca node_modules/edgeaegis/tools/.build/scr/cli/main.js deploy local";
await writeFile(resolve(directory, "package.json"), `${JSON.stringify(p, null, 2)}\n`);
console.log(
  "Isolated TLS origins, two business functions and five independent demo keys prepared.",
);
