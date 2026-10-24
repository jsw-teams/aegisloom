/** Bound remote allocations while streaming; checking response.text().length afterwards is too late. */
export async function boundedJson(
  response: Response,
  maxBytes = 4000000,
  timeoutMs = 10000,
): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Empty JSON response");
  let timer: ReturnType<typeof setTimeout> | undefined;
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("Remote body deadline exceeded")), timeoutMs);
    });
    await Promise.race([
      (async () => {
        while (true) {
          const item = await reader.read();
          if (item.done) break;
          length += item.value.byteLength;
          if (length > maxBytes) throw new Error("Remote JSON response exceeds byte limit");
          chunks.push(item.value.slice());
        }
      })(),
      timeout,
    ]);
  } catch (error) {
    void reader.cancel().catch(() => {});
    throw error;
  } finally {
    if (timer) clearTimeout(timer);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}
