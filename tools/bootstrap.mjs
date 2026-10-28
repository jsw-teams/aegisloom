import { existsSync } from "node:fs";
import { lstat, mkdir, rename, rm, symlink } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
const dependencies = resolve(root, "tools/node_modules");
if (dependencies !== resolve(root, "tools", "node_modules"))
  throw new Error("Invalid dependency directory");
if (existsSync(resolve(root, "node_modules"))) {
  if (existsSync(dependencies)) await rm(dependencies, { recursive: true, force: true });
  await mkdir(dirname(dependencies), { recursive: true });
  await rename(resolve(root, "node_modules"), dependencies);
}
const sourceLink = resolve(root, "scr/node_modules");
try {
  const current = await lstat(sourceLink);
  if (!current.isSymbolicLink()) throw new Error("Source dependencies must be a generated link");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
  await symlink(dependencies, sourceLink, process.platform === "win32" ? "junction" : "dir");
}
