import { DOMParser } from "@xmldom/xmldom";
import xpath from "xpath";
import { formEntries, fromOctets, utf8Bytes } from "./bytes.js";
import { jsonArguments } from "./json.js";

export type BodyProcessor = "" | "URLENCODED" | "JSON" | "XML" | "MULTIPART";
export function bodyProcessor(headers: Headers): BodyProcessor {
  const type = headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (type === "application/x-www-form-urlencoded") return "URLENCODED";
  if (type === "application/json") return "JSON";
  if (type === "text/xml" || type === "application/xml") return "XML";
  if (type === "multipart/form-data") return "MULTIPART";
  return "";
}

export function parseBody(
  body: string,
  headers: Headers,
  processor: BodyProcessor,
  bytes?: Uint8Array,
  maxBodyBytes = 2 * 1024 * 1024,
) {
  const args: [string, string][] = [];
  const files: { name: string; filename: string; size: number }[] = [];
  const partHeaders: [string, string][] = [];
  let xml: ReturnType<DOMParser["parseFromString"]> | undefined;
  if ((bytes?.length ?? new TextEncoder().encode(body).length) > maxBodyBytes)
    throw new Error("SecLang body limit exceeded");
  const binary = bytes ? fromOctets(bytes) : utf8Bytes(body);
  if (processor === "URLENCODED") args.push(...formEntries(binary, true));
  if (bytes && (processor === "JSON" || processor === "XML"))
    body = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (processor === "JSON" && body) {
    args.push(
      ...jsonArguments(body).map(
        ([path, value]) => [utf8Bytes(path), utf8Bytes(value)] as [string, string],
      ),
    );
  }
  if (processor === "XML" && body) {
    if (/<!DOCTYPE|<!ENTITY/i.test(body)) throw new Error("XML DTD/entities are disabled");
    xml = new DOMParser({
      onError: (_level, message) => {
        throw new Error(`Invalid XML: ${message}`);
      },
    }).parseFromString(body, "application/xml");
  }
  if (processor === "MULTIPART" && binary) {
    body = binary;
    const type = headers.get("content-type") ?? "";
    const boundary = /(?:^|;)\s*boundary=(?:"([^"\r\n]+)"|([^;\s]+))/i.exec(type);
    const token = boundary?.[1] ?? boundary?.[2];
    if (!token || token.length > 70 || !/^[\x20-\x7e]+$/.test(token))
      throw new Error("Invalid multipart boundary");
    const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const delimiters: RegExpMatchArray[] = [];
    for (const match of body.matchAll(
      new RegExp(`(?:^|\\r?\\n)--${escaped}(--)?[ \\t]*(?:\\r?\\n|$)`, "g"),
    )) {
      delimiters.push(match);
      if (delimiters.length > 129) throw new Error("Multipart part limit exceeded");
      if (match[1]) break;
    }
    if (!delimiters.length || !delimiters.at(-1)?.[1]) throw new Error("Malformed multipart body");
    for (let i = 0; i < delimiters.length - 1; i++) {
      const opening = delimiters[i]!,
        next = delimiters[i + 1]!;
      const part = body.slice(opening.index! + opening[0].length, next.index!);
      const separator = /\r?\n\r?\n/.exec(part),
        end = separator?.index ?? -1;
      if (end < 0 || end > 16384) throw new Error("Invalid multipart part headers");
      const lines = part.slice(0, end).split(/\r?\n/);
      const disposition = lines.find((line) => /^content-disposition:/i.test(line));
      if (lines.filter((line) => /^content-disposition:/i.test(line)).length !== 1)
        throw new Error("Ambiguous multipart disposition");
      const parameter = (name: "name" | "filename") => {
        const pattern =
          name === "name"
            ? /(?:^|;)\s*name=(?:"((?:\\.|[^"\\\r\n])*)"|([^;\s]*))/i
            : /(?:^|;)\s*filename=(?:"((?:\\.|[^"\\\r\n])*)"|([^;\s]*))/i;
        const match = pattern.exec(disposition ?? "");
        return match ? (match[1] ?? match[2] ?? "").replace(/\\(["\\])/g, "$1") : undefined;
      };
      const name = parameter("name");
      if (name === undefined) throw new Error("Multipart field name missing");
      const filename = parameter("filename");
      for (const line of lines) {
        if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+:[^\0\r\n]*$/.test(line))
          throw new Error("Invalid multipart header");
        partHeaders.push([name, line]);
      }
      const content = part.slice(end + separator![0].length);
      if (filename !== undefined)
        files.push({
          name,
          filename,
          size: content.length,
        });
      else args.push([name, content]);
    }
  }
  return { args, files, partHeaders, xml };
}

export function xmlValues(
  document: NonNullable<ReturnType<typeof parseBody>["xml"]>,
  expression: string,
): [string, string][] {
  const result = xpath.select(expression, document as unknown as Node);
  if (!Array.isArray(result)) return [[expression, String(result)]];
  return result.map((value, index) => [
    String(index),
    typeof value === "object" && value !== null
      ? ((value as Node).textContent ?? "")
      : String(value),
  ]);
}
