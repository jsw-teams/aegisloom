#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { SHIELD_VERSION } from "../core/version.js";
export async function main(args = process.argv.slice(2)) {
  const [command, file] = args;
  if (command === "--version" || command === "-v") {
    console.log(SHIELD_VERSION);
    return;
  }
  if (!command || command === "--help") {
    console.log(
      "edgeaegis init [directory]\nedgeaegis build <cloudflare|vercel|netlify|esa|edgeone|local> [config.yml]\nedgeaegis start <platform|local> [config.yml] [--plan]\nedgeaegis deploy <platform|local> [config.yml] [--plan]\nedgeaegis service <install|start|stop|status> [config.yml] [--system]\nedgeaegis serve [config.yml]\nedgeaegis serve-relay <secret/relay-server.yml>\nedgeaegis check <SecLang file or source bundle>\nedgeaegis sync [--registry path] [--output path]\nedgeaegis --version",
    );
    return;
  }
  if (command === "init") {
    await (await import("./init.js")).initProject(file ?? ".");
    return;
  }
  if (command === "service") {
    const positional = args.slice(2).filter((value) => value !== "--system");
    if (!file || positional.length > 1)
      throw Error("edgeaegis service <install|start|stop|status> [config.yml] [--system]");
    await (await import("./service.js")).service(
      file,
      positional[0] ?? "config.yml",
      args.includes("--system"),
    );
    return;
  }
  if (["build", "start", "deploy"].includes(command!) && file) {
    if (file === "local") {
      const rest = args.slice(2).filter((value) => value !== "--plan");
      if (rest.length > 1) throw new Error("Unexpected command arguments");
      const configFile = rest[0] ?? "config.yml";
      if (args.includes("--plan")) {
        console.log(
          JSON.stringify({
            platform: "local",
            tool: "node",
            args: ["edgeaegis", "start", "local", configFile],
          }),
        );
        return;
      }
      if (command !== "build") {
        await (await import("./serve.js")).serve(configFile);
        return;
      }
      const { config } = await (await import("./deployment.js")).readDeployment(configFile);
      await (await import("./config.js")).readCredentials(config.secretFile);
      const native = await (await import("../seclang/node.js")).loadSecLangDeployment(
        config.secLangFile,
        config.localRulesFile,
        config.setupRulesFile,
      );
      const program = (await import("../seclang/index.js")).compileSecLang(native.secLang, {
        ...native.secLangOptions,
        strict: true,
      });
      try {
        console.log(
          JSON.stringify({
            platform: "local",
            sourceRules: program.sourceRules,
            unsupported: program.unsupported.length,
          }),
        );
      } finally {
        program.dispose();
      }
      return;
    }
    execFileSync(
      process.execPath,
      [fileURLToPath(new URL("../../../platform-command.mjs", import.meta.url)), ...args],
      { stdio: "inherit", windowsHide: true },
    );
    return;
  }
  if (command === "sync") {
    execFileSync(
      process.execPath,
      [
        fileURLToPath(new URL("../../../sync-native-seclang.mjs", import.meta.url)),
        ...args.slice(1),
      ],
      { stdio: "inherit" },
    );
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
