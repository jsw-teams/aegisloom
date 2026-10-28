import { copyFile, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { transform } from "esbuild";

const from = new URL("../scr/seclang/vendor/", import.meta.url);
const to = new URL(".build/scr/seclang/vendor/", import.meta.url);
await mkdir(to, { recursive: true });
for (const file of await readdir(from)) await copyFile(new URL(file, from), new URL(file, to));
// Publish generic adapter templates so the installed CLI needs no source checkout.
for (const file of [
  "handler",
  ...["cloudflare", "vercel", "netlify", "esa", "edgeone"].map((p) => `${p}/worker`),
]) {
  const source = new URL(`../scr/adapters/${file}.ts`, import.meta.url),
    target = new URL(`.build/scr/adapters/${file}.js`, import.meta.url);
  await mkdir(new URL(".", target), { recursive: true });
  await writeFile(
    target,
    (
      await transform(await readFile(source, "utf8"), {
        loader: "ts",
        format: "esm",
        target: "es2022",
      })
    ).code,
  );
}
