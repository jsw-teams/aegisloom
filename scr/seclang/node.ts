import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import type { CompileSecLangOptions } from "./index.js";
import { createInjectionDetectors } from "./libinjection.js";
import { createPCRE2Backend } from "./pcre2.js";

let backends: Promise<Pick<CompileSecLangOptions, "regexBackend" | "detectors">> | undefined;
export async function loadSecLangDeployment(
  entry: string,
  localRulesFile?: string,
  setupRulesFile?: string,
) {
  const native = await loadSecLangFile(entry);
  const files = { ...native.secLangOptions.files };
  const sources = [native.secLang];
  const paths = new Set([resolve(entry)]);
  for (const [path, prefix] of [
    [setupRulesFile, true],
    [localRulesFile, false],
  ] as const) {
    if (!path) continue;
    if (paths.has(resolve(path))) throw new Error("Operator rules must have separate entry files");
    paths.add(resolve(path));
    const operator = await loadSecLangFile(path);
    for (const [name, text] of Object.entries(operator.secLangOptions.files ?? {})) {
      if (files[name] !== undefined && files[name] !== text)
        throw new Error(`Local rule file collides with upstream file: ${name}`);
      files[name] = text;
    }
    // An explicit Include preserves the source-relative scope of nested Includes/data.
    const source = `Include ${basename(path)}`;
    if (prefix) sources.unshift(source);
    else sources.push(source);
  }
  return {
    secLang: sources.join("\n"),
    secLangOptions: { ...native.secLangOptions, files },
  };
}
export function loadSecLangBackends() {
  backends ??= Promise.all([
    readFile(new URL("./vendor/pcre2.wasm", import.meta.url)).then(createPCRE2Backend),
    readFile(new URL("./vendor/libinjection.wasm", import.meta.url)).then(createInjectionDetectors),
  ]).then(([regexBackend, detectors]) => ({ regexBackend, detectors }));
  return backends;
}

/** Load a bounded, local rule bundle; Include never resolves outside the entry directory. */
export async function loadSecLangFile(
  entry: string,
): Promise<{ secLang: string; secLangOptions: CompileSecLangOptions }> {
  const absolute = resolve(entry),
    root = dirname(absolute);
  if (absolute.endsWith(".json")) {
    const raw = await readFile(absolute);
    if (raw.length > 32 * 1024 * 1024) throw new Error("SecLang JSON bundle exceeds 32 MiB");
    const bundle = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw),
    );
    if (
      bundle.version !== 1 ||
      bundle.format !== "seclang-source-bundle" ||
      typeof bundle.source !== "string" ||
      !bundle.files ||
      typeof bundle.files !== "object" ||
      Array.isArray(bundle.files)
    )
      throw new Error("Invalid SecLang source bundle");
    let bytes = 0;
    for (const [path, text] of Object.entries(bundle.files)) {
      if (typeof text !== "string" || path.startsWith("/") || path.split("/").includes(".."))
        throw new Error("Invalid SecLang bundled file");
      bytes += new TextEncoder().encode(text).length;
    }
    if (bytes > 16 * 1024 * 1024 || Object.keys(bundle.files).length > 4096)
      throw new Error("SecLang bundle resource limit");
    for (const upstream of bundle.upstreams ?? [])
      for (const file of upstream.files ?? []) {
        if (
          typeof bundle.files[file.path] !== "string" ||
          createHash("sha256").update(bundle.files[file.path]).digest("hex") !== file.sha256
        )
          throw new Error(`SecLang bundled file integrity mismatch: ${file.path}`);
      }
    return {
      secLang: bundle.source,
      secLangOptions: { files: bundle.files, ...(await loadSecLangBackends()) },
    };
  }
  const files: Record<string, string> = {};
  let size = 0,
    count = 0;
  async function scan(directory: string, depth: number): Promise<void> {
    if (depth > 32) throw new Error("SecLang source directory depth exceeded");
    for (const item of await readdir(directory, { withFileTypes: true })) {
      if (item.name.startsWith(".") || item.name === "node_modules") continue;
      const path = join(directory, item.name);
      if (item.isDirectory()) await scan(path, depth + 1);
      else if (
        item.isFile() &&
        (/\.(conf|data|txt|ipset|list|example|mapping|map)$/.test(item.name) || path === absolute)
      ) {
        if (++count > 4096) throw new Error("SecLang source file count exceeded");
        const bytes = await readFile(path);
        size += bytes.length;
        if (size > 16 * 1024 * 1024) throw new Error("SecLang source bundle exceeds 16 MiB");
        files[relative(root, path).replace(/\\/g, "/")] = new TextDecoder("utf-8", {
          fatal: true,
          ignoreBOM: true,
        }).decode(bytes);
      }
    }
  }
  await scan(root, 0);
  const fileName = basename(absolute);
  const secLang = files[fileName];
  if (secLang === undefined) throw new Error("SecLang entry file was not loaded");
  return { secLang, secLangOptions: { files, fileName, ...(await loadSecLangBackends()) } };
}
