import { octets } from "./bytes.js";
export interface InjectionDetectors {
  sqli(value: string): { matched: boolean; fingerprint: string };
  xss(value: string): boolean;
}

/** Only tokenizer/detector primitives are imported; SecLang execution stays first-party. */
export async function createInjectionDetectors(
  module: WebAssembly.Module | BufferSource,
): Promise<InjectionDetectors> {
  const loaded = await WebAssembly.instantiate(module as WebAssembly.Module, {});
  const instance =
    loaded instanceof WebAssembly.Instance
      ? loaded
      : (loaded as WebAssembly.WebAssemblyInstantiatedSource).instance;
  const api = instance.exports as unknown as {
    memory: WebAssembly.Memory;
    malloc(size: number): number;
    free(ptr: number): void;
    libinjection_sqli(ptr: number, length: number, fingerprint: number): number;
    libinjection_xss(ptr: number, length: number): number;
    _initialize?(): void;
  };
  api._initialize?.();
  function inspect<T>(value: string, fn: (ptr: number, length: number) => T): T {
    const bytes = octets(value);
    if (bytes.length > 2 * 1024 * 1024) throw new Error("Libinjection input exceeds limit");
    const ptr = api.malloc(bytes.length + 1);
    if (!ptr) throw new Error("Libinjection allocation failed");
    try {
      new Uint8Array(api.memory.buffer, ptr, bytes.length).set(bytes);
      return fn(ptr, bytes.length);
    } finally {
      api.free(ptr);
    }
  }
  return {
    sqli(value) {
      return inspect(value, (ptr, length) => {
        const fp = api.malloc(8);
        if (!fp) throw new Error("Libinjection fingerprint allocation failed");
        try {
          const rc = api.libinjection_sqli(ptr, length, fp);
          if (rc < 0) throw new Error("Libinjection SQLi error");
          const buffer = new Uint8Array(api.memory.buffer, fp, 8);
          const end = buffer.indexOf(0);
          if (end < 0) throw new Error("Libinjection fingerprint is unterminated");
          return {
            matched: rc === 1,
            fingerprint: new TextDecoder().decode(buffer.subarray(0, end)),
          };
        } finally {
          api.free(fp);
        }
      });
    },
    xss(value) {
      return inspect(value, (ptr, length) => {
        const rc = api.libinjection_xss(ptr, length);
        if (rc < 0) throw new Error("Libinjection XSS error");
        return rc === 1;
      });
    },
  };
}
