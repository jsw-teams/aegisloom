import { copyFile, mkdir, readdir } from "node:fs/promises";

const from = new URL("../scr/seclang/vendor/", import.meta.url);
const to = new URL(".build/scr/seclang/vendor/", import.meta.url);
await mkdir(to, { recursive: true });
for (const file of await readdir(from)) await copyFile(new URL(file, from), new URL(file, to));
