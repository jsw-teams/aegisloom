import data from "./vendor/unicode.json" with { type: "json" };
export const defaultUnicodeMap = new Map(
  Object.entries(data.mapping).map(([code, value]) => [Number(code), value]),
);
export function parseUnicodeMap(text: string, codepage: number) {
  const lines = text.split(/\r?\n/),
    start = lines.findIndex((line) => new RegExp(`^${codepage}\\s`).test(line));
  if (start < 0) throw new Error("Requested Unicode codepage is absent");
  const mapping = new Map<number, number>();
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\d+\s/.test(line)) break;
    for (const match of line.matchAll(/\b([a-f\d]{4}):([a-f\d]{2})\b/gi))
      mapping.set(Number.parseInt(match[1]!, 16), Number.parseInt(match[2]!, 16));
  }
  if (!mapping.size) throw new Error("Unicode mapping table is empty");
  return mapping;
}
