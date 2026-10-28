import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";

const directory = new URL("../secret/", import.meta.url);
await mkdir(directory, { recursive: true });
try {
  await writeFile(
    new URL("credentials.yml", directory),
    `originToken: ${randomBytes(32).toString("base64url")}\ningressKey: ${randomBytes(32).toString("base64url")}\n`,
    { flag: "wx", mode: 0o600 },
  );
  console.log("Created private project credentials in secret/credentials.yml");
} catch (error) {
  if (error.code !== "EEXIST") throw error;
}
