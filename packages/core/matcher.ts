import { RE2JS } from "re2js";
import type { Expression, Match } from "../rule-ir/types.js";
import { ShieldError, type TrustedContext } from "./types.js";

export interface MatchInput {
  request: Request;
  url: URL;
  path: string;
  bodyText: string;
  json?: unknown;
  context: TrustedContext;
}
export type Predicate = (input: MatchInput) => boolean;

function pointer(value: unknown, key: string): unknown {
  for (const part of key
    .slice(1)
    .split("/")
    .map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"))) {
    if (!value || typeof value !== "object" || !Object.hasOwn(value, part)) return undefined;
    value = (value as Record<string, unknown>)[part];
  }
  return value;
}
function values(m: Match, i: MatchInput): unknown[] {
  switch (m.field) {
    case "path":
      return [i.path];
    case "method":
      return [i.request.method];
    case "header":
      return i.request.headers.has(m.key ?? "") ? [i.request.headers.get(m.key ?? "")] : [];
    case "query":
      return i.url.searchParams.getAll(m.key ?? "");
    case "body": {
      const v = m.key ? pointer(i.json, m.key) : i.bodyText;
      return v === undefined ? [] : [v];
    }
    case "identity":
      return i.context.identity === undefined ? [] : [i.context.identity];
    case "client.ip":
      return i.context.verifiedClientIp === undefined ? [] : [i.context.verifiedClientIp];
    case "client.class":
      return i.context.clientClass === undefined ? [] : [i.context.clientClass];
    case "risk.score":
      return i.context.riskScore === undefined ? [] : [i.context.riskScore];
  }
}
export function compileExpression(expr: Expression): Predicate {
  if ("all" in expr) {
    const terms = expr.all.map(compileExpression);
    return (i) => terms.every((fn) => fn(i));
  }
  if ("any" in expr) {
    const terms = expr.any.map(compileExpression);
    return (i) => terms.some((fn) => fn(i));
  }
  if ("not" in expr) {
    const fn = compileExpression(expr.not);
    return (i) => !fn(i);
  }
  const regex = expr.op === "regex" ? RE2JS.compile(String(expr.value)) : undefined;
  return (input) => {
    const fields = values(expr, input);
    if (expr.op === "exists") return fields.length > 0 === expr.value;
    return fields.some((raw) => {
      if (!["string", "number", "boolean"].includes(typeof raw)) return false;
      let value = String(raw);
      if (value.length > 262144) throw new ShieldError("match-input-too-large", 413);
      for (const transform of expr.transforms ?? []) {
        if (transform === "lowercase") value = value.toLowerCase();
        else if (transform === "trim") value = value.trim();
        else {
          try {
            value = decodeURIComponent(value);
          } catch {
            throw new ShieldError("invalid-rule-decoding");
          }
        }
      }
      switch (expr.op) {
        case "eq":
          return value === String(expr.value);
        case "contains":
          return value.includes(String(expr.value));
        case "prefix":
          return value.startsWith(String(expr.value));
        case "regex":
          return regex?.matcher(value).find() ?? false;
        case "range": {
          if (!/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(value)) return false;
          const n = Number(value);
          return (
            Number.isFinite(n) &&
            (expr.min === undefined || n >= expr.min) &&
            (expr.max === undefined || n <= expr.max)
          );
        }
        default:
          return false;
      }
    });
  };
}
