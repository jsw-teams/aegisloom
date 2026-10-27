import { readFileSync, writeFileSync } from "node:fs";
import { loadPolicy, policyVersion } from "@jsw-teams/edgeshield/rules";
import { parse, stringify } from "yaml";

const file = process.argv[2];
if (!file || !/^[a-z-]+\.json$/.test(file)) throw new Error("Local candidate filename required");
const policy = loadPolicy(JSON.parse(readFileSync(file, "utf8")));
for (const id of ["a", "b"]) {
  const config = parse(readFileSync(`${id}.yaml`, "utf8"));
  config.policyFile = file;
  writeFileSync(`${id}.yaml`, stringify(config));
}
console.log(
  JSON.stringify({
    activatedFile: file,
    policy: await policyVersion(policy),
    restartRequired: true,
  }),
);
