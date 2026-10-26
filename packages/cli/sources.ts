import { open } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";
import type { ConversionReport } from "../../integrations/rule-converter/index.js";
import {
  importSource,
  type SourceConfig,
  validateSources,
} from "../../integrations/rule-converter/sources.js";
import type { Policy } from "../rule-ir/index.js";
import { readData } from "./config.js";

export async function readSources(path: string): Promise<SourceConfig> {
  return validateSources(await readData(path));
}
export async function importConfiguredSource(
  file: string,
  id: string,
  report?: ConversionReport,
  transport: typeof fetch = fetch,
): Promise<Policy> {
  const config = await readSources(file);
  const source = config.ruleSources.find((s) => s.id === id && s.enabled);
  if (!source) throw new Error("Unknown or disabled rule source");
  const bytes = await downloadSource(file, source, transport);
  return importSource(config, id, bytes, report);
}

/** Background-only bounded reader. Credentials are restricted to the exact configured URL. */
export async function downloadSource(
  file: string,
  source: SourceConfig["ruleSources"][number],
  transport: typeof fetch = fetch,
): Promise<Uint8Array> {
  let bytes: Uint8Array;
  if (source.location.startsWith("https://")) {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), 5000);
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    try {
      const headers = new Headers({
        "accept-encoding": "identity",
        accept: "application/vnd.github.raw+json",
      });
      if (source.authTokenEnv) {
        const token = process.env[source.authTokenEnv];
        if (!token || !/^[\x21-\x7e]{8,2048}$/.test(token))
          throw new Error("Missing source credential");
        headers.set("authorization", `Bearer ${token}`);
      }
      const response = await transport(source.location, {
        redirect: "error",
        signal: abort.signal,
        headers,
      });
      if (
        response.status !== 200 ||
        !response.body ||
        ![null, "identity"].includes(response.headers.get("content-encoding"))
      )
        throw new Error("Rule source requires a non-redirected, uncompressed HTTP 200 response");
      reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 131072) throw new Error("Rule source exceeds 128KiB");
        chunks.push(value);
      }
      bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }
    } finally {
      clearTimeout(timer);
      abort.abort();
      await reader?.cancel().catch(() => {});
    }
  } else {
    const base = dirname(resolve(file)),
      path = resolve(base, source.location);
    if (!path.startsWith(base + sep)) throw new Error("Rule file escaped configuration directory");
    // Fixed-size read bounds memory even when a trusted operator accidentally selects a huge file.
    const handle = await open(path, "r");
    try {
      const data = new Uint8Array(131073);
      let length = 0;
      while (length < data.length) {
        const part = await handle.read(data, length, data.length - length, null);
        if (!part.bytesRead) break;
        length += part.bytesRead;
      }
      if (length > 131072) throw new Error("Rule source exceeds 128KiB");
      bytes = data.slice(0, length);
    } finally {
      await handle.close();
    }
  }
  return bytes;
}
