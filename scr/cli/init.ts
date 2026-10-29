import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { SHIELD_VERSION } from "../core/version.js";
/** Materialize operator files outside node_modules; existing files are never overwritten. */
export async function initProject(target: string) {
  let root = dirname(fileURLToPath(import.meta.url));
  let found = false;
  for (let i = 0; i < 6; i++) {
    try {
      if (JSON.parse(await readFile(join(root, "package.json"), "utf8")).name === "edgeaegis") {
        found = true;
        break;
      }
    } catch {}
    root = dirname(root);
  }
  if (!found) throw new Error("Cannot locate installed EdgeAegis package");
  const directory = resolve(target);
  const files = [
    "config.yml",
    "origin/config.yml",
    "rules/config.yml",
    "rules/seclang-bundle.json",
    "rules/seclang-upstreams.json",
    "rules/allowlist.yml",
    "rules/local.conf",
    "rules/setup.conf",
    "rules/emergency.conf",
    "secret/credentials.example.yml",
    "respond/403.html",
    "respond/403.json",
    "secret/relay-server.example.yml",
    ...["cloudflare", "vercel", "netlify", "esa", "edgeone"].flatMap((platform) => [
      `origin/${platform}/app/index.js`,
    ]),
  ];
  async function put(path: string, data: string | Uint8Array) {
    const destination = join(directory, path);
    await mkdir(dirname(destination), { recursive: true });
    try {
      await writeFile(destination, data, { flag: "wx", mode: 0o600 });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  }
  for (const file of files) await put(file, await readFile(join(root, file)));
  await put(
    "secret/credentials.yml",
    `originKeys:\n  app: ${randomBytes(32).toString("base64url")}\ningressKey: ${randomBytes(32).toString("base64url")}\n`,
  );
  const scripts: Record<string, string> = {};
  for (const platform of ["cloudflare", "vercel", "netlify", "esa", "edgeone", "local"])
    for (const command of ["build", "start", "deploy"])
      scripts[`${command}:${platform}`] = `edgeaegis ${command} ${platform}`;
  await put(
    "package.json",
    `${JSON.stringify({ private: true, type: "module", scripts, dependencies: { edgeaegis: `^${SHIELD_VERSION}` } }, null, 2)}\n`,
  );
  await put(".gitignore", "secret/*\n!secret/credentials.example.yml\ntools/.state/\n");
  console.log(`Initialized operator files in ${directory}`);
}
