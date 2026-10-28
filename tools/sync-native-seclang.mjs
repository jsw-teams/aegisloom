import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { verifyFullCrs } from "./verify-full-crs.mjs";

const registryUrl = new URL("../rules/seclang-upstreams.json", import.meta.url);
const registry = JSON.parse(await readFile(registryUrl, "utf8"));
if (registry.version !== 1 || !Array.isArray(registry.sources) || !registry.sources.length)
  throw new Error("Invalid SecLang upstream registry");
const update = process.argv.includes("--latest");
const files = {},
  upstreams = [];
let total = 0,
  source = "";
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
async function github(path, limit = 2 * 1024 * 1024) {
  const token = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN;
  const response = await fetch(`https://api.github.com/${path}`, {
    redirect: "error",
    signal: AbortSignal.timeout(30000),
    headers: {
      accept: "application/vnd.github+json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!response.ok) throw new Error(`GitHub source request failed: HTTP ${response.status}`);
  const chunks = [];
  let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length;
    if (length > limit) throw new Error("Upstream response exceeds limit");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks));
}
const ids = new Set();
for (const spec of registry.sources) {
  if (
    !/^[a-z0-9-]{1,64}$/.test(spec.id) ||
    ids.has(spec.id) ||
    !/^[\w.-]+\/[\w.-]+$/.test(spec.repository) ||
    ![spec.rulesDirectory, spec.setup, spec.license].every(
      (path) =>
        typeof path === "string" && !path.startsWith("/") && !path.split("/").includes(".."),
    )
  )
    throw new Error("Invalid SecLang source");
  ids.add(spec.id);
  const ref = update
    ? (await github(`repos/${spec.repository}/releases/latest`)).tag_name
    : spec.ref;
  if (typeof ref !== "string" || ref.length > 128) throw new Error("Invalid upstream ref");
  const commit = (await github(`repos/${spec.repository}/commits/${encodeURIComponent(ref)}`)).sha;
  if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error("Invalid upstream commit");
  const tree = await github(
    `repos/${spec.repository}/git/trees/${commit}?recursive=1`,
    8 * 1024 * 1024,
  );
  if (tree.truncated || !Array.isArray(tree.tree)) throw new Error("Incomplete upstream tree");
  const entries = tree.tree.filter(
    (item) =>
      item.type === "blob" &&
      ((item.path.startsWith(`${spec.rulesDirectory}/`) && /\.(conf|data)$/.test(item.path)) ||
        item.path === spec.setup ||
        item.path === spec.license),
  );
  if (
    !entries.some((item) => item.path === spec.setup) ||
    !entries.some((item) => item.path === spec.license)
  )
    throw new Error("Missing upstream setup/license");
  const manifest = [];
  for (const item of entries) {
    const blob = await github(`repos/${spec.repository}/git/blobs/${item.sha}`, 4 * 1024 * 1024);
    if (blob.encoding !== "base64" || blob.sha !== item.sha)
      throw new Error("Unexpected upstream blob");
    const bytes = Buffer.from(blob.content, "base64");
    total += bytes.length;
    if (total > 16 * 1024 * 1024 || bytes.length > 2 * 1024 * 1024)
      throw new Error("SecLang source bundle exceeds limit");
    const gitHash = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
    if (gitHash !== item.sha) throw new Error("Upstream Git blob hash mismatch");
    const path = `${spec.id}/${item.path === spec.setup ? "setup.conf" : item.path}`;
    files[path] = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    manifest.push({ path, bytes: bytes.length, sha256: digest(bytes), gitBlob: item.sha });
  }
  source += `Include ${spec.id}/setup.conf\nInclude ${spec.id}/${spec.rulesDirectory}/*.conf\n`;
  upstreams.push({ id: spec.id, repository: spec.repository, ref, commit, files: manifest });
  spec.ref = ref;
}
const bundle = { version: 1, format: "seclang-source-bundle", source, files, upstreams };
const validation = await verifyFullCrs(bundle);
const destination = new URL("../rules/seclang-bundle.json", import.meta.url);
await mkdir(new URL("../rules/", import.meta.url), { recursive: true });
const temporary = new URL("../rules/seclang-bundle.json.tmp", import.meta.url);
await writeFile(temporary, `${JSON.stringify(bundle, null, 2)}\n`);
await rename(temporary, destination);
if (update) await writeFile(registryUrl, `${JSON.stringify(registry, null, 2)}\n`);
console.log(
  JSON.stringify({
    upstreams: upstreams.map(({ id, ref, commit }) => ({ id, ref, commit })),
    validation,
  }),
);
