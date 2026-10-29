const fs = require("node:fs");
const [command, name] = process.argv.slice(2);
if (command === "view") {
  process.stdout.write(
    JSON.stringify(
      name === "fixture-leaf"
        ? process.env.TEST_UNPATCHABLE
          ? ["1.0.0", "2.0.0"]
          : ["1.0.0", "1.0.2"]
        : ["1.0.0"],
    ),
  );
} else if (command === "install") {
  fs.writeFileSync(
    "package-lock.json",
    JSON.stringify({
      packages: {
        "node_modules/fixture-leaf": {
          version: "1.0.0",
          ...(process.env.TEST_DEPRECATED ? { deprecated: "Use the maintained replacement" } : {}),
        },
      },
    }),
  );
} else if (command === "audit") {
  const manifest = JSON.parse(fs.readFileSync("package.json"));
  if (manifest.scripts) throw new Error("Lifecycle scripts must not enter resolution snapshots");
  const fixed = manifest.overrides?.["fixture-leaf"] === "^1.0.2";
  process.stdout.write(
    JSON.stringify({
      metadata: { vulnerabilities: { high: fixed ? 0 : 1 } },
      vulnerabilities: fixed
        ? {}
        : {
            "fixture-leaf": {
              severity: "high",
              via: [{ range: "<1.0.2" }],
              nodes: ["node_modules/fixture-leaf"],
            },
          },
    }),
  );
  process.exitCode = fixed ? 0 : 1;
} else throw new Error("Unexpected mock npm operation");
