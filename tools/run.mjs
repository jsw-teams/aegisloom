import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const executables = {
  tsc: "typescript/lib/tsc.js",
  biome: "@biomejs/biome/bin/biome",
  tsx: "tsx/dist/cli.mjs",
  wrangler: "wrangler/bin/wrangler.js",
};
const [command, ...args] = process.argv.slice(2);
if (!Object.hasOwn(executables, command)) throw new Error("Unknown project tool");
const child = spawn(
  process.execPath,
  [fileURLToPath(new URL(`./node_modules/${executables[command]}`, import.meta.url)), ...args],
  { stdio: "inherit", windowsHide: true },
);
child.once("error", (error) => {
  console.error(error.message);
  process.exitCode = 1;
});
child.once("exit", (code) => {
  process.exitCode = code ?? 1;
});
