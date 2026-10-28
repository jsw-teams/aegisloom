#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { SHIELD_VERSION } from "../core/version.js";
export async function main(args = process.argv.slice(2)) {
  const [command, file] = args;
  if (command === "--version" || command === "-v") {
    console.log(SHIELD_VERSION);
    return;
  }
  if (!command || command === "--help") {
    console.log(
      "edgeshield init [directory]\nedgeshield serve [config.yml]\nedgeshield serve-relay <secret/relay-server.yml>\nedgeshield check <SecLang file or source bundle>\nedgeshield --version",
    );
    return;
  }
  if (command === "init") {
    await (await import("./init.js")).initProject(file ?? ".");
    return;
  }
  if (command === "serve") {
    await (await import("./serve.js")).serve(file ?? "config.yml");
    return;
  }
  if (command === "serve-relay" && file) {
    await (await import("./relay-serve.js")).serveRelay(file);
    return;
  }
  if (command === "check" && file) {
    const { loadSecLangFile } = await import("../seclang/node.js");
    const { compileSecLang } = await import("../seclang/index.js");
    const loaded = await loadSecLangFile(file);
    const program = compileSecLang(loaded.secLang, { ...loaded.secLangOptions, strict: true });
    try {
      console.log(
        JSON.stringify({
          sourceRules: program.sourceRules,
          rootRules: program.supportedRules,
          unsupported: program.unsupported.length,
        }),
      );
    } finally {
      program.dispose();
    }
    return;
  }
  throw new Error("Unknown command or missing rule file");
}
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href)
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
