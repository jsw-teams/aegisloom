import { ShieldError } from "../core/types.js";

/** Reject parser differentials: duplicate object keys, non-finite numbers and excessive nesting. */
export function parseStrictJson(text: string): unknown {
  let offset = 0;
  let nodes = 0;
  const ws = () => {
    while (/[\x20\t\r\n]/.test(text[offset] ?? "!")) offset++;
  };
  const fail = (): never => {
    throw new ShieldError("ambiguous-or-invalid-json");
  };
  function string(): string {
    const start = offset;
    if (text[offset++] !== '"') return fail();
    while (offset < text.length) {
      const c = text[offset++];
      if (c === '"') {
        try {
          return JSON.parse(text.slice(start, offset)) as string;
        } catch {
          return fail();
        }
      }
      if (c === "\\") offset++;
    }
    return fail();
  }
  function value(depth: number): void {
    if (depth > 32 || ++nodes > 16384) fail();
    ws();
    const c = text[offset];
    if (c === '"') {
      string();
      return;
    }
    if (c === "{" || c === "[") {
      const object = c === "{";
      const close = object ? "}" : "]";
      const keys = new Set<string>();
      offset++;
      ws();
      if (text[offset] === close) {
        offset++;
        return;
      }
      while (true) {
        if (object) {
          ws();
          const key = string();
          if (keys.has(key)) fail();
          keys.add(key);
          ws();
          if (text[offset++] !== ":") fail();
        }
        value(depth + 1);
        ws();
        if (text[offset] === close) {
          offset++;
          return;
        }
        if (text[offset++] !== ",") fail();
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(
      text.slice(offset),
    )?.[0];
    if (!token) throw new ShieldError("ambiguous-or-invalid-json");
    if (/^-?[0-9]/.test(token) && !Number.isFinite(Number(token))) fail();
    offset += token.length;
  }
  value(0);
  ws();
  if (offset !== text.length) fail();
  try {
    return JSON.parse(text);
  } catch {
    return fail();
  }
}
