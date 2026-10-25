import { readFileSync } from "node:fs";

const lines = readFileSync(`${process.argv[2] || "a"}.events.jsonl`, "utf8")
  .trim()
  .split("\n")
  .filter(Boolean);
const event = JSON.parse(lines.at(-1));
if (process.argv.includes("--id")) console.log(event.decisionId);
else
  console.log(
    JSON.stringify(
      {
        source: event.source,
        kind: event.kind,
        ruleId: event.ruleId,
        decisionId: event.decisionId,
        reason: event.reason,
      },
      null,
      2,
    ),
  );
