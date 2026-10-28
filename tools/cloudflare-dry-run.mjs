import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildPlatform } from "./build-platform.mjs";

const root = resolve(import.meta.dirname, ".."),
  file = resolve(process.argv[2] ?? "config.yml");
const built = await buildPlatform("cloudflare", file);
const wrangler = {
  name: "edgeshield",
  main: built.entry,
  compatibility_date: "2026-10-01",
  workers_dev: false,
  preview_urls: false,
  routes: [],
  send_metrics: false,
  no_bundle: true,
  rules: [{ type: "CompiledWasm", globs: ["**/*.wasm"], fallthrough: false }],
};
const path = resolve(built.directory, "wrangler.json");
await writeFile(path, JSON.stringify(wrangler, null, 2));
execFileSync(
  process.execPath,
  [
    resolve(root, "tools/run.mjs"),
    "wrangler",
    "deploy",
    "--dry-run",
    "--config",
    path,
    "--outdir",
    resolve(root, "tools/.cache/cloudflare-dry-run"),
  ],
  { cwd: built.directory, stdio: "inherit", windowsHide: true },
);
