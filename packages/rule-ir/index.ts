import { RE2JS } from "re2js";
import { parseDocument } from "yaml";
import { digest, stableJson } from "../core/types.js";
import schema from "./schema.json" with { type: "json" };
import type { Expression, Policy, Rule } from "./types.js";
import generatedValidator from "./validator.js";

export type * from "./types.js";
export { schema };

const validate = generatedValidator as import("ajv").ValidateFunction;
export function duration(input: string): number {
  const match = /^([1-9][0-9]{0,5})(ms|s|m|h)$/.exec(input);
  if (!match) throw new Error(`Invalid duration: ${input}`);
  const result = Number(match[1]) * ({ ms: 1, s: 1000, m: 60000, h: 3600000 }[match[2] ?? ""] ?? 0);
  if (result < 1 || result > 86_400_000) throw new Error("Duration must be <=24h");
  return result;
}

function boundedTree(input: unknown, depth = 0, counter = { n: 0 }): void {
  if (depth > 20 || ++counter.n > 16000) throw new Error("Policy complexity limit exceeded");
  if (input && typeof input === "object") {
    for (const [key, value] of Object.entries(input)) {
      if (["__proto__", "constructor", "prototype"].includes(key))
        throw new Error("Unsafe policy key");
      boundedTree(value, depth + 1, counter);
    }
  }
}

export function visit(
  expr: Expression,
  fn: (leaf: Extract<Expression, { field: string }>) => void,
): void {
  if ("all" in expr) for (const e of expr.all) visit(e, fn);
  else if ("any" in expr) for (const e of expr.any) visit(e, fn);
  else if ("not" in expr) visit(expr.not, fn);
  else fn(expr);
}

export function loadPolicy(source: string | unknown): Policy {
  let raw: unknown = source;
  if (typeof source === "string") {
    if (new TextEncoder().encode(source).length > 131072) throw new Error("Policy exceeds 128KiB");
    const doc = parseDocument(source, { uniqueKeys: true, merge: false });
    if (doc.errors.length) throw new Error(doc.errors.map((e) => e.message).join("; "));
    raw = doc.toJS({ maxAliasCount: 0 });
  }
  boundedTree(raw);
  if (!validate(raw)) throw new Error(`Shield IR validation: ${JSON.stringify(validate.errors)}`);
  const copy = structuredClone(raw) as { version: "1"; rules: Record<string, any>[] };
  const rules: Rule[] = copy.rules.map((r) => {
    const when = r.when;
    if ("path" in when || "method" in when || "requests" in when) {
      if (r.requests && when.requests) throw new Error("Duplicate frequency condition");
      if (when.requests) r.requests = when.requests;
      const all: Expression[] = [];
      if (when.path) all.push({ field: "path", op: "eq", value: when.path });
      if (when.method) all.push({ field: "method", op: "eq", value: when.method });
      if (!all.length) throw new Error("Frequency sugar requires a path or method scope");
      r.when = { all };
    }
    return {
      enabled: true,
      priority: 100,
      phase: "request-headers",
      placement: "runtime-required",
      cache: { enabled: false, ttl: "1m" },
      community: { report: false },
      ...r,
    } as Rule;
  });
  const ids = new Set<string>();
  for (const rule of rules) {
    if (ids.has(rule.id)) throw new Error(`Duplicate rule id: ${rule.id}`);
    ids.add(rule.id);
    duration(rule.cache.ttl);
    if (rule.then.duration) duration(rule.then.duration);
    if (rule.then.duration && rule.then.action !== "rate-limit")
      throw new Error("duration is only implemented for rate-limit actions");
    if (rule.then.score !== undefined && rule.then.action !== "detect")
      throw new Error("score accumulation requires a detect action");
    if (rule.requests) duration(rule.requests.within);
    if (rule.then.action === "rate-limit" && (!rule.requests || !rule.then.duration))
      throw new Error("Rate limit requires frequency and duration");
    if (rule.requests && rule.cache.enabled)
      throw new Error("Stateful rules cannot use exact-request decision caching");
    if (
      rule.expiresAt &&
      (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(rule.expiresAt) ||
        !Number.isFinite(Date.parse(rule.expiresAt)))
    )
      throw new Error("Invalid expiresAt; UTC ISO required");
    visit(rule.when, (m) => {
      if (m.op !== "range" && (m.min !== undefined || m.max !== undefined))
        throw new Error("Numeric bounds require range operator");
      if (m.op === "range" && m.value !== undefined)
        throw new Error("range uses min/max, not value");
      if (m.op === "exists" && m.transforms?.length)
        throw new Error("Existence checks cannot apply value transforms");
      if (["header", "query"].includes(m.field) && !m.key)
        throw new Error("Header/query requires key");
      if (m.key && !["header", "query", "body"].includes(m.field))
        throw new Error("Unexpected field key");
      if (m.field === "header" && !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(m.key ?? ""))
        throw new Error("Invalid header name");
      if (m.op === "exists") {
        if (typeof m.value !== "boolean") throw new Error("exists requires boolean");
      } else if (m.op === "range") {
        if (
          (m.min === undefined && m.max === undefined) ||
          (m.min !== undefined && m.max !== undefined && m.min > m.max)
        )
          throw new Error("Invalid numeric range");
      } else if (m.value === undefined || typeof m.value === "boolean")
        throw new Error("Comparison requires string/number");
      if (m.op === "regex") {
        if (typeof m.value !== "string" || m.value.length > 256)
          throw new Error("Regex exceeds 256 characters");
        if (/[{}]/.test(m.value))
          throw new Error("Counted repetition is outside the bounded regex profile");
        RE2JS.compile(m.value);
      }
      if (m.field === "body" && rule.phase !== "request-body")
        throw new Error("Body matching requires request-body phase");
      if (m.field === "body" && m.key && !/^\/(?:[^~]|~[01])*$/.test(m.key))
        throw new Error("Body key must be a JSON pointer");
    });
  }
  const policy: Policy = {
    version: "1",
    rules: rules.sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id)),
  };
  const conflicts = findConflicts(policy);
  if (conflicts.length) throw new Error(conflicts.join("; "));
  return policy;
}

export function findConflicts(policy: Policy): string[] {
  const result: string[] = [];
  for (let i = 0; i < policy.rules.length; i++) {
    const a = policy.rules[i];
    if (!a?.enabled) continue;
    for (const b of policy.rules.slice(i + 1)) {
      if (
        b.enabled &&
        a.service === b.service &&
        a.priority === b.priority &&
        stableJson(a.when) === stableJson(b.when) &&
        a.then.action !== b.then.action
      )
        result.push(`Conflict: ${a.id}/${b.id}; set explicit priorities`);
    }
  }
  return result;
}

export async function policyVersion(policy: Policy): Promise<string> {
  return digest(stableJson(policy));
}
export function explain(rule: Rule): string {
  return `${rule.id}: ${rule.name}; service=${rule.service}; phase=${rule.phase}; priority=${rule.priority}; when=${stableJson(rule.when)}${rule.requests ? `; frequency >${rule.requests.moreThan}/${rule.requests.within} by ${rule.requests.groupBy}` : ""}; action=${rule.then.action}; cache=${rule.cache.enabled}; expires=${rule.expiresAt ?? "never"}`;
}
