import { open } from "node:fs/promises";
import { parseConfigText, validateCredentials } from "../config.js";
export async function readData(path: string, limit = 8_000_000): Promise<unknown> {
  const file = await open(path, "r");
  try {
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const chunk of file.createReadStream({ autoClose: false, highWaterMark: 65536 })) {
      length += chunk.length;
      if (length > limit) throw new Error("Configuration input exceeds byte limit");
      chunks.push(chunk);
    }
    return parseConfigText(Buffer.concat(chunks, length).toString("utf8"));
  } finally {
    await file.close();
  }
}
export async function readCredentials(path: string) {
  return validateCredentials(await readData(path, 16384));
}
