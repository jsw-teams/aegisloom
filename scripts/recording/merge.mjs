import { readFileSync, writeFileSync } from "node:fs";
import { loadPolicy } from "@jsw-teams/edgeshield/rules";

const read = (file) => loadPolicy(JSON.parse(readFileSync(file, "utf8")));
const merged = loadPolicy({
  version: "1",
  rules: [...read("candidate.json").rules, ...read("candidate-method.json").rules],
});
writeFileSync("merged-policy.json", JSON.stringify(merged, null, 2));
console.log(
  JSON.stringify({ validated: true, rules: merged.rules.length, output: "merged-policy.json" }),
);
