import { rm } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
const target = resolve(root, "tools/.build");
if (target !== resolve(root, "tools", ".build")) throw new Error("Invalid build output path");
await rm(target, { recursive: true, force: true });
