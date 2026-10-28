/** First-party SecLang lexer: preserves multiline statements, directives and actions. */
export interface SecLangStatement {
  line: number;
  directive: string;
  args: string[];
  raw: string;
  file?: string;
}
export function parseSecLangSyntax(input: string): SecLangStatement[] {
  if (typeof input !== "string") throw new TypeError("SecLang input must be text");
  const statements = [];
  let pending = "",
    start = 1;
  const lines = input.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (!pending && (!line || line.startsWith("#"))) continue;
    if (!pending) start = i + 1;
    const backslashes = /\\+$/.exec(line)?.[0].length ?? 0;
    const continued = backslashes % 2 === 1;
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
      quote: string | null = null,
      escaped = false,
      started = false;
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
        started = true;
        continue;
      }
      if (ch === quote) {
        quote = null;
        continue;
      }
      if (!quote && /\s/.test(ch)) {
        if (started) {
          parts.push(part);
          part = "";
          started = false;
        }
      } else {
        part += ch;
        started = true;
      }
    }
    if (quote) throw new Error(`Unterminated quote at line ${line}`);
    if (started) parts.push(part);
    const [directive, ...args] = parts;
    if (!directive) throw new Error(`Empty SecLang directive at line ${line}`);
    if (directive === "SecRule" && (args.length < 2 || args.length > 3))
      throw new Error(`Malformed SecRule at line ${line}`);
    if (directive === "SecAction" && args.length !== 1)
      throw new Error(`Malformed SecAction at line ${line}`);
    return { line, directive, args, raw };
  });
}
