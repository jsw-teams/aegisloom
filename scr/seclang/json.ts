/** Flatten JSON scalars without rounding numeric tokens or discarding duplicate members. */
export function jsonArguments(text: string): [string, string][] {
  const result: [string, string][] = [];
  let offset = 0,
    nodes = 0;
  const fail = (): never => {
    throw new Error("Invalid SecLang JSON body");
  };
  const space = () => {
    while (/[\x20\t\r\n]/.test(text[offset] ?? "!")) offset++;
  };
  function string() {
    const start = offset;
    if (text[offset++] !== '"') return fail();
    while (offset < text.length) {
      const c = text[offset++];
      if (c === '"') {
        let value: string;
        try {
          value = JSON.parse(text.slice(start, offset));
        } catch {
          return fail();
        }
        if (/[\ud800-\udfff]/u.test(value)) return fail();
        return value;
      }
      if (c === "\\") offset++;
    }
    return fail();
  }
  function value(path: string, depth: number) {
    if (depth > 64 || ++nodes > 16384 || result.length >= 4096)
      throw new Error("SecLang JSON nesting/argument limit");
    space();
    const first = text[offset];
    if (first === "{" || first === "[") {
      offset++;
      space();
      const object = first === "{",
        close = object ? "}" : "]";
      if (text[offset] === close) {
        offset++;
        return;
      }
      let index = 0;
      while (true) {
        let child: string;
        if (object) {
          space();
          const key = string();
          space();
          if (text[offset++] !== ":") return fail();
          child = `${path}.${key}`;
        } else child = `${path}.array_${index++}`;
        value(child, depth + 1);
        space();
        if (text[offset] === close) {
          offset++;
          return;
        }
        if (text[offset++] !== ",") return fail();
      }
    }
    if (first === '"') {
      result.push([path, string()]);
      return;
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
      text.slice(offset),
    )?.[0];
    if (!token) return fail();
    offset += token.length;
    result.push([path, token === "null" ? "" : token]);
  }
  value("json", 0);
  space();
  if (offset !== text.length) return fail();
  return result;
}
