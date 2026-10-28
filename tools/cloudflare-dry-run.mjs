import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { buildPlatform } from "./build-platform.mjs";

const root = resolve(import.meta.dirname, ".."),
  file = resolve(process.argv[2] ?? "config.yml");
const built = await buildPlatform("cloudflare", file);
const path = resolve(built.deployDirectory, "wrangler.json");
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
  { cwd: built.deployDirectory, stdio: "inherit", windowsHide: true },
);
