import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildPlatform } from "./build-platform.mjs";
export async function platformCommand(
  command,
  platform,
  file = "config.yml",
  { plan = false } = {},
) {
  const providers = {
    cloudflare: ["wrangler", "wrangler", ["dev"], ["deploy"]],
    vercel: ["vercel", "vercel", ["dev"], ["deploy", "--prod"]],
    netlify: ["netlify-cli", "netlify", ["dev"], ["deploy", "--prod", "--no-build"]],
    esa: ["esa-cli", "esa-cli", ["dev"], ["deploy"]],
    edgeone: ["edgeone", "edgeone", ["makers", "dev"], ["makers", "deploy"]],
  };
  if (!Object.hasOwn(providers, platform) || !["build", "start", "deploy"].includes(command))
    throw Error("Unknown platform command");
  const built = await buildPlatform(platform, resolve(file));
  if (command === "build") return built;
  const [packageName, tool, dev, deploy] = providers[platform],
    args = [...(command === "start" ? dev : deploy)];
  if (platform === "cloudflare") args.push("--config", "wrangler.json");
  const result = { platform, tool, args, cwd: built.deployDirectory };
  if (plan) return result;
  let entry;
  for (const location of [dirname(resolve(file)), resolve(dirname(file), "tools")])
    try {
      const require = createRequire(join(location, "package.json"));
      const manifestFile = require.resolve(`${packageName}/package.json`),
        manifest = JSON.parse(await readFile(manifestFile, "utf8"));
      const bin = typeof manifest.bin === "string" ? manifest.bin : manifest.bin?.[tool];
      if (bin) {
        entry = resolve(dirname(manifestFile), bin);
        break;
      }
    } catch {}
  if (!entry)
    throw Error(`Install ${packageName} in the deployment project before running ${tool}`);
  execFileSync(process.execPath, [entry, ...args], {
    cwd: result.cwd,
    stdio: "inherit",
    windowsHide: true,
  });
  return result;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, platform, ...rest] = process.argv.slice(2),
    positional = rest.filter((v) => v !== "--plan");
  if (positional.length > 1) throw Error("Unexpected command arguments");
  console.log(
    JSON.stringify(
      await platformCommand(command, platform, positional[0], { plan: rest.includes("--plan") }),
    ),
  );
}
