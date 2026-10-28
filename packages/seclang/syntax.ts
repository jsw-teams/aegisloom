// @ts-nocheck
/** First-party SecLang lexer: preserves multiline statements, directives and actions. */
export function parseSecLangSyntax(input) {
  if (typeof input !== "string") throw new TypeError("SecLang input must be text");
  const statements = [];
  let pending = "",
    start = 1;
  const lines = input.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!pending && (!line || line.startsWith("#"))) continue;
    if (!pending) start = i + 1;
    const continued = line.endsWith("\\");
    pending += (continued ? line.slice(0, -1) : line) + (continued ? " " : "");
    if (!continued) {
      statements.push({ line: start, raw: pending });
      pending = "";
    }
  }
  if (pending) throw new Error(`Incomplete continuation at line ${start}`);
  return statements.map(({ line, raw }) => {
    const parts = [];
    let part = "",
      quote = null,
      escaped = false;
    for (const ch of raw) {
      if (escaped) {
        part += ch;
        escaped = false;
        continue;
      }
      if (ch === "\\" && quote) {
        part += ch;
        escaped = true;
        continue;
      }
      if ((ch === "'" || ch === '"') && !quote) {
        quote = ch;
        continue;
      }
      if (ch === quote) {
        quote = null;
        continue;
      }
      if (!quote && /\s/.test(ch)) {
        if (part) {
          parts.push(part);
          part = "";
        }
      } else part += ch;
    }
    if (quote) throw new Error(`Unterminated quote at line ${line}`);
    if (part) parts.push(part);
    const [directive, ...args] = parts;
    if (directive === "SecRule" && (args.length < 2 || args.length > 3))
      throw new Error(`Malformed SecRule at line ${line}`);
    return { line, directive, args, raw };
  });
}
