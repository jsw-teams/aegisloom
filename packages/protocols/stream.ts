import { requireInteger } from "../core/types.js";

export interface MediaProfile {
  headerTimeoutMs: number;
  idleTimeoutMs: number;
  maxBytes: number;
  contentTypes: string[];
}
export function validateMediaProfile(input: MediaProfile): MediaProfile {
  const p = structuredClone(input);
  if (
    !p ||
    Object.keys(p).some(
      (k) => !["headerTimeoutMs", "idleTimeoutMs", "maxBytes", "contentTypes"].includes(k),
    )
  )
    throw new Error("Invalid media profile");
  requireInteger(p.headerTimeoutMs, 1, 120000, "media header deadline");
  requireInteger(p.idleTimeoutMs, 1, 300000, "media idle deadline");
  requireInteger(p.maxBytes, 1, 1073741824, "media transfer limit");
  if (
    !Array.isArray(p.contentTypes) ||
    !p.contentTypes.length ||
    p.contentTypes.length > 32 ||
    p.contentTypes.some((v) => !/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(v))
  )
    throw new Error("Explicit media MIME types required");
  return p;
}
/** No fixed total deadline: continuously progressing transfers can last longer than headerTimeoutMs. */
export function protectStream(
  input: ReadableStream<Uint8Array>,
  options: {
    maxBytes: number;
    idleTimeoutMs: number;
    signal: AbortSignal;
    abort: () => void;
    complete: () => void;
    inspect?: (bytes: Uint8Array, final: boolean) => void;
  },
): ReadableStream<Uint8Array> {
  requireInteger(options.maxBytes, 1, 1073741824, "stream bytes");
  requireInteger(options.idleTimeoutMs, 1, 300000, "stream idle deadline");
  const reader = input.getReader();
  let controller: ReadableStreamDefaultController<Uint8Array>;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let ended = false;
  let total = 0;
  const cleanup = () => {
    if (ended) return;
    ended = true;
    if (timer) clearTimeout(timer);
    options.signal.removeEventListener("abort", interrupted);
    options.complete();
  };
  const fail = (error: Error) => {
    if (ended) return;
    cleanup();
    options.abort();
    void reader.cancel(error).catch(() => {});
    controller.error(error);
  };
  const interrupted = () => fail(new Error("origin-stream-aborted"));
  const reset = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fail(new Error("origin-stream-idle-timeout")), options.idleTimeoutMs);
  };
  return new ReadableStream<Uint8Array>({
    start(c) {
      controller = c;
      options.signal.addEventListener("abort", interrupted, { once: true });
      if (options.signal.aborted) interrupted();
      else reset();
    },
    async pull(c) {
      if (ended) return;
      try {
        const item = await reader.read();
        if (ended) return;
        if (item.done) {
          options.inspect?.(new Uint8Array(), true);
          cleanup();
          c.close();
          return;
        }
        total += item.value.byteLength;
        if (total > options.maxBytes) throw new Error("origin-response-too-large");
        options.inspect?.(item.value, false);
        reset();
        c.enqueue(item.value);
      } catch (error) {
        fail(error instanceof Error ? error : new Error("stream-failure"));
      }
    },
    cancel(reason) {
      cleanup();
      options.abort();
      return reader.cancel(reason);
    },
  });
}

export function validateRange(value: string | null): void {
  // Single range only; origin remains responsible for object length and authorization.
  if (value === null) return;
  if (value.length > 64 || !/^bytes=(?:[0-9]{1,16}-[0-9]{0,16}|-[0-9]{1,16})$/.test(value))
    throw new Error("unsupported-media-range");
  const [start, end] = value.slice(6).split("-");
  if (
    (start && !Number.isSafeInteger(Number(start))) ||
    (end && !Number.isSafeInteger(Number(end))) ||
    (start && end && Number(end) < Number(start)) ||
    (!start && Number(end) === 0)
  )
    throw new Error("invalid-media-range");
}
