import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const directory = new URL("../secret/relay/", import.meta.url);
await mkdir(directory, { recursive: true });
const existing = await Promise.all(
  ["private.jwk", "public.jwk", "authentication.key"].map(async (name) => {
    try {
      await access(new URL(name, directory));
      return true;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      return false;
    }
  }),
);
if (existing.every(Boolean)) {
  console.log("Existing relay key retained");
} else {
  if (existing.some(Boolean))
    throw new Error(
      "Incomplete existing relay key set; restore missing files before initialization",
    );
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const privateKey = await crypto.subtle.exportKey("jwk", pair.privateKey),
    publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  await writeFile(new URL("private.jwk", directory), `${JSON.stringify(privateKey, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  await writeFile(new URL("public.jwk", directory), `${JSON.stringify(publicKey, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  const key = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
  await writeFile(new URL("authentication.key", directory), `${key}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  console.log(`Created relay key files in ${fileURLToPath(directory)}`);
}
try {
  await writeFile(
    new URL("../secret/relay-server.yml", import.meta.url),
    await readFile(new URL("../secret/relay-server.example.yml", import.meta.url)),
    { flag: "wx", mode: 0o600 },
  );
} catch (error) {
  if (error.code !== "EEXIST") throw error;
}
