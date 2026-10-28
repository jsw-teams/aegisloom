import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { parseStrictJson } from "../http-boundary/json.js";
import type { ErrorPages } from "../runtime/error-pages.js";
export async function readResponsePages(directory: string, csp: string): Promise<ErrorPages> {
  const pages: ErrorPages = {};
  const names = await readdir(directory);
  if (names.length > 100) throw new Error("Too many custom response files");
  for (const name of names) {
    const match = /^([45]\d\d)\.html$/.exec(name);
    if (!match) continue;
    const bytes = await readFile(join(directory, name));
    if (bytes.length > 262144) throw new Error("Custom response HTML exceeds 256 KiB");
    const status = Number(match[1]);
    pages[status] = {
      html: new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      contentSecurityPolicy: csp,
    };
    const jsonName = `${status}.json`;
    if (names.includes(jsonName)) {
      const raw = await readFile(join(directory, jsonName));
      if (raw.length > 65536) throw new Error("Custom response JSON exceeds 64 KiB");
      pages[status]!.json = parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(raw));
    }
  }
  return pages;
}
