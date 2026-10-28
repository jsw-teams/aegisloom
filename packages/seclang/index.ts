// @ts-nocheck
/**
 * EdgeShield's first-party SecLang state machine (no ModSecurity process).
 * Compiles a strictly verified subset and reports unsupported semantics.
 * Data is a Request-like object or real Web Request; no I/O occurs while executing.
 */
import { RE2JS } from "re2js";
import { parseSecLangSyntax } from "./syntax.js";

export function splitActions(source) {
  const entries = [];
  let current = "";
  let quote = false;
  let escaped = false;
  for (const ch of source) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      current += ch;
      escaped = true;
      continue;
    }
    if (ch === "'") quote = !quote;
    if (ch === "," && !quote) {
      entries.push(current.trim());
      current = "";
    } else current += ch;
  }
  if (quote) throw new Error("Unterminated SecLang action quote");
  if (current.trim()) entries.push(current.trim());
  return entries;
}

function parseActions(text) {
  const out = [];
  for (const part of splitActions(text)) {
    const colon = part.indexOf(":");
    const name = (colon < 0 ? part : part.slice(0, colon)).toLowerCase();
    let arg = colon < 0 ? undefined : part.slice(colon + 1);
    if (arg?.startsWith("'") && arg.endsWith("'")) arg = arg.slice(1, -1);
    out.push({ name, arg });
  }
  return out;
}

const ACTIONS = new Set([
  "id",
  "phase",
  "deny",
  "block",
  "pass",
  "log",
  "nolog",
  "auditlog",
  "noauditlog",
  "t",
  "msg",
  "logdata",
  "tag",
  "ver",
  "severity",
  "rev",
  "maturity",
  "accuracy",
  "chain",
  "setvar",
  "skipafter",
  "status",
  "capture",
]);
const OPERATOR_NAMES = new Set([
  "streq",
  "contains",
  "beginswith",
  "endswith",
  "within",
  "eq",
  "lt",
  "le",
  "ge",
  "gt",
  "rx",
  "pm",
  "pmfromfile",
]);
const TRANSFORM_NAMES = new Set([
  "none",
  "lowercase",
  "uppercase",
  "trim",
  "trimleft",
  "trimright",
  "urldecode",
  "compresswhitespace",
  "removewhitespace",
  "removenulls",
]);
const VARIABLES = new Set([
  "REQUEST_METHOD",
  "REQUEST_URI",
  "REQUEST_URI_RAW",
  "REQUEST_FILENAME",
  "REQUEST_BASENAME",
  "REQUEST_HEADERS",
  "REQUEST_HEADERS_NAMES",
  "REQUEST_COOKIES",
  "REQUEST_COOKIES_NAMES",
  "REQUEST_BODY",
  "ARGS",
  "ARGS_NAMES",
  "QUERY_STRING",
  "TX",
  "REQUEST_PROTOCOL",
]);

function compilerError(message, statement) {
  return {
    line: statement.line,
    reason: message,
    rule: statement.args?.[2]?.match(/id:(\d+)/)?.[1],
  };
}

function compileSelector(text) {
  const selectors = [];
  for (const entry of text.split("|")) {
    const negative = entry.startsWith("!");
    const part = negative ? entry.slice(1) : entry;
    const count = part.startsWith("&");
    const field = count ? part.slice(1) : part;
    const colon = field.indexOf(":");
    const key = colon < 0 ? undefined : field.slice(colon + 1);
    const name = (colon < 0 ? field : field.slice(0, colon)).toUpperCase();
    if (!VARIABLES.has(name)) throw new Error(`Unsupported variable collection: ${name}`);
    if (key?.includes("%{")) throw new Error("Dynamic selector macros are not supported");
    selectors.push({ negative, count, name, key });
  }
  if (!selectors.length || selectors.every((x) => x.negative))
    throw new Error("No positive variable selector");
  return selectors;
}
function compileOperator(text, phraseFiles) {
  const negated = text.startsWith("!");
  const raw = negated ? text.slice(1) : text;
  const m = /^@([A-Za-z]+)(?:\s+([\s\S]*))?$/.exec(raw);
  if (!m) throw new Error("Unsupported implicit operator");
  const op = m[1].toLowerCase();
  const operand = m[2] ?? "";
  if (!OPERATOR_NAMES.has(op)) throw new Error(`Unsupported operator ${op}`);
  if (operand.includes("%{")) throw new Error("Runtime operator macros are not implemented");
  let regex: RE2JS | undefined;
  if (op === "rx") {
    if (operand.includes("(?<") || /\\[1-9]/.test(operand))
      throw new Error("PCRE lookbehind/backreference requires a compatible regex backend");
    try {
      regex = RE2JS.compile(operand);
    } catch (error) {
      throw new Error(`Regex not in RE2 subset: ${String(error.message)}`);
    }
  }
  const numeric = ["eq", "lt", "le", "ge", "gt"].includes(op);
  if (numeric && !/^-?\d+(?:\.\d+)?$/.test(operand))
    throw new Error("Numeric operator requires a literal number");
  let phrases: string[] | undefined;
  if (op === "pmfromfile") {
    phrases = phraseFiles?.[operand];
    if (!Array.isArray(phrases) || !phrases.every((v) => typeof v === "string"))
      throw new Error(`Missing explicit phrase file: ${operand}`);
  } else if (op === "pm") phrases = operand.split(/\s+/).filter(Boolean);
  return { op, operand, negated, regex, phrases };
}
function compileActionSet(actions) {
  const data = { phase: undefined, transformations: [], changes: [] };
  for (const { name, arg } of actions) {
    if (!ACTIONS.has(name)) throw new Error(`Unsupported action ${name}`);
    if (name === "phase") {
      const phase = Number(arg);
      if (![1, 2].includes(phase)) throw new Error("Unsupported SecLang phase");
      data.phase = phase;
    } else if (name === "id") {
      if (!/^\d{1,10}$/.test(arg ?? "")) throw new Error("Invalid rule id");
      data.id = arg;
    } else if (name === "chain") data.chain = true;
    else if (["deny", "block", "pass"].includes(name)) data.decision = name;
    else if (name === "t") {
      const v = arg?.toLowerCase();
      if (!TRANSFORM_NAMES.has(v)) throw new Error(`Unsupported transform ${arg}`);
      if (v === "none") data.transformations = [];
      else data.transformations.push(v);
    } else if (name === "setvar") {
      const m = /^(tx\.[a-zA-Z0-9_.-]+)=((?:[+-])?[\s\S]+)$/.exec(arg ?? "");
      if (!m) throw new Error("Unsupported setvar expression");
      if (/%\{(?!tx\.[a-zA-Z0-9_.-]+\})/i.test(m[2])) throw new Error("Unsupported setvar macro");
      data.changes.push({ name: m[1].slice(3).toLowerCase(), value: m[2] });
    } else if (name === "skipafter") data.skipAfter = arg;
    else if (name === "status") {
      if (!/^[45]\d\d$/.test(arg ?? "")) throw new Error("Unsupported status");
      data.status = Number(arg);
    } else if (name === "capture") {
      throw new Error("Capture semantics not implemented");
    } else if (name === "msg") data.message = arg;
  }
  if (data.transformations.length > 24) throw new Error("Too many transforms");
  return data;
}

/** Compile an entire file; strict mode prevents using a partial CRS policy as a full WAF. */
export function compileSecLang(source, { phraseFiles = {}, strict = false } = {}) {
  const statements = parseSecLangSyntax(source);
  const instructions = [];
  const unsupported = [];
  let prior = null;
  const ids = new Set();
  for (const stmt of statements) {
    if (stmt.directive === "SecMarker" && stmt.args.length === 1) {
      instructions.push({ type: "marker", name: stmt.args[0], line: stmt.line });
      prior = null;
      continue;
    }
    if (stmt.directive !== "SecRule") {
      unsupported.push(compilerError(`Unsupported directive: ${stmt.directive}`, stmt));
      prior = null;
      continue;
    }
    try {
      const [selectorsText, operatorText, actionText = ""] = stmt.args;
      const selectors = compileSelector(selectorsText);
      const operator = compileOperator(operatorText, phraseFiles);
      const actions = compileActionSet(parseActions(actionText));
      const step = { type: "rule", selectors, operator, actions, line: stmt.line };
      if (prior?.actions.chain) {
        step.actions.phase ??= prior.actions.phase;
        prior.next = step;
      } else {
        if (!actions.id) throw new Error("Root rule requires id");
        actions.phase ??= 2;
        if (ids.has(actions.id)) throw new Error(`Duplicate rule id ${actions.id}`);
        ids.add(actions.id);
        instructions.push(step);
      }
      prior = step;
    } catch (error) {
      unsupported.push(compilerError(String(error.message), stmt));
      prior = null;
    }
  }
  // Do not silently execute a truncated/incomplete chain.
  for (const item of instructions.filter((i) => i.type === "rule")) {
    let node = item;
    while (node.actions.chain) {
      if (!node.next) {
        unsupported.push({ line: node.line, reason: "Incomplete chain", rule: item.actions.id });
        item.invalid = true;
        break;
      }
      node = node.next;
    }
  }
  if (unsupported.length && strict) {
    const first = unsupported[0];
    throw new Error(`SecLang unsupported at line ${first.line}: ${first.reason}`);
  }
  return {
    instructions: instructions.filter((item) => !item.invalid),
    unsupported,
    supportedRules: instructions.filter((item) => item.type === "rule" && !item.invalid).length,
    sourceRules: statements.filter((item) => item.directive === "SecRule").length,
  };
}
function transformed(value, transforms) {
  let result = String(value);
  for (const op of transforms) {
    if (op === "lowercase") result = result.toLowerCase();
    else if (op === "uppercase") result = result.toUpperCase();
    else if (op === "trim") result = result.trim();
    else if (op === "trimleft") result = result.trimStart();
    else if (op === "trimright") result = result.trimEnd();
    else if (op === "compresswhitespace") result = result.replace(/\s+/g, " ");
    else if (op === "removewhitespace") result = result.replace(/\s+/g, "");
    else if (op === "removenulls") result = result.replace(/\0/g, "");
    else if (op === "urldecode") {
      try {
        result = decodeURIComponent(result.replace(/\+/g, " "));
      } catch {
        throw new Error("Invalid encoded SecLang input");
      }
    }
  }
  if (result.length > 262144) throw new Error("Transformed input exceeds policy size limit");
  return result;
}
function values(selector, request, tx) {
  const url = new URL(request.url);
  const headers = new Headers(request.headers ?? {});
  let entries = [];
  const qs = [...url.searchParams];
  // ARGS in phase 2 includes URL-encoded form data where the caller supplies
  // the already bounded request body. JSON/XML processors are not presumed.
  const contentType = headers.get("content-type")?.split(";")[0].trim().toLowerCase();
  if (contentType === "application/x-www-form-urlencoded" && request.bodyText) {
    if (request.bodyText.length > 262144) throw new Error("Request body exceeds VM limit");
    qs.push(...new URLSearchParams(request.bodyText));
  }
  const cookies = (headers.get("cookie") || "")
    .split(/;\s*/)
    .filter(Boolean)
    .map((part) => {
      const at = part.indexOf("=");
      return [part.slice(0, at).trim(), at < 0 ? "" : part.slice(at + 1)];
    });
  switch (selector.name) {
    case "REQUEST_METHOD":
      entries = [["REQUEST_METHOD", request.method]];
      break;
    case "REQUEST_URI":
      entries = [["REQUEST_URI", url.pathname + url.search]];
      break;
    case "REQUEST_URI_RAW":
      entries = [["REQUEST_URI_RAW", url.pathname + url.search]];
      break;
    case "REQUEST_FILENAME":
      entries = [["REQUEST_FILENAME", url.pathname]];
      break;
    case "REQUEST_BASENAME":
      entries = [["REQUEST_BASENAME", url.pathname.split("/").pop()]];
      break;
    case "REQUEST_PROTOCOL":
      entries = request.protocol ? [["REQUEST_PROTOCOL", request.protocol]] : [];
      break;
    case "QUERY_STRING":
      entries = [["QUERY_STRING", url.search.slice(1)]];
      break;
    case "REQUEST_HEADERS":
      entries = [...headers.entries()];
      break;
    case "REQUEST_HEADERS_NAMES":
      entries = [...headers.keys()].map((v) => [v, v]);
      break;
    case "REQUEST_BODY":
      entries = [["REQUEST_BODY", request.bodyText ?? ""]];
      break;
    case "ARGS":
      entries = qs;
      break;
    case "ARGS_NAMES":
      entries = qs.map(([k]) => [k, k]);
      break;
    case "REQUEST_COOKIES":
      entries = cookies;
      break;
    case "REQUEST_COOKIES_NAMES":
      entries = cookies.map(([k]) => [k, k]);
      break;
    case "TX":
      entries = [...tx].map(([k, v]) => [k, String(v)]);
      break;
  }
  if (selector.key !== undefined)
    entries = entries.filter(([k]) => k.toLowerCase() === selector.key.toLowerCase());
  return selector.count ? [["count", String(entries.length)]] : entries;
}
function getValues(selectors, request, tx) {
  const selected = [];
  for (const item of selectors) {
    if (item.negative) continue;
    for (const [key, value] of values(item, request, tx)) {
      const excluded = selectors.some(
        (negative) =>
          negative.negative &&
          negative.name === item.name &&
          (negative.key === undefined || negative.key.toLowerCase() === key.toLowerCase()),
      );
      if (!excluded) selected.push(String(value));
    }
  }
  return selected;
}

function compares(value, condition) {
  const { op, operand, regex, phrases } = condition;
  switch (op) {
    case "streq":
      return value === operand;
    case "contains":
      return value.includes(operand);
    case "beginswith":
      return value.startsWith(operand);
    case "endswith":
      return value.endsWith(operand);
    case "within":
      return operand.includes(value);
    case "rx":
      return regex.matcher(value).find();
    case "pm":
    case "pmfromfile":
      return phrases.some((phrase) => value.toLowerCase().includes(phrase.toLowerCase()));
    case "eq":
      return Number(value) === Number(operand);
    case "lt":
      return Number(value) < Number(operand);
    case "le":
      return Number(value) <= Number(operand);
    case "gt":
      return Number(value) > Number(operand);
    case "ge":
      return Number(value) >= Number(operand);
  }
  return false;
}
function match(step, request, tx) {
  const source = getValues(step.selectors, request, tx);
  return source.some((raw) => {
    const value = transformed(raw, step.actions.transformations);
    const result = compares(value, step.operator);
    return step.operator.negated ? !result : result;
  });
}
function macro(value, tx) {
  return value.replace(/%\{tx\.([a-zA-Z0-9_.-]+)\}/gi, (_, key) =>
    String(tx.get(key.toLowerCase()) ?? ""),
  );
}
function updateState(changes, tx) {
  for (const change of changes) {
    const evaluated = macro(change.value, tx);
    const arithmetic = /^([+-])(\d+(?:\.\d+)?)$/.exec(evaluated);
    if (arithmetic) {
      const current = Number(tx.get(change.name) ?? 0);
      const delta = Number(arithmetic[2]) * (arithmetic[1] === "+" ? 1 : -1);
      if (!Number.isFinite(current + delta)) throw new Error("Invalid TX arithmetic");
      tx.set(change.name, current + delta);
    } else tx.set(change.name, evaluated);
  }
}
/** Evaluate request phases with per-transaction TX state and deterministic order. */
export function executeSecLang(
  program,
  request,
  { tx: inputTx = {}, phases = [1, 2], anomalyThreshold, shouldSkip } = {},
) {
  if (program.unsupported.length)
    throw new Error("Cannot run an incompletely compiled SecLang policy");
  if (!request || typeof request.url !== "string" || typeof request.method !== "string")
    throw new TypeError("SecLang VM requires a URL and method");
  const tx = new Map(Object.entries(inputTx).map(([k, v]) => [k.toLowerCase(), v]));
  const matched = [];
  let blocked = false;
  let status = 403;
  for (const phase of phases) {
    let skipUntil: string | undefined;
    for (const rule of program.instructions) {
      if (rule.type === "marker") {
        if (skipUntil === rule.name) skipUntil = undefined;
        continue;
      }
      if (skipUntil) continue;
      if (shouldSkip?.(rule.actions.id)) continue;
      let current = rule,
        allMatched = true;
      while (current) {
        const effectivePhase = current.actions.phase ?? rule.actions.phase;
        if (effectivePhase !== phase || !match(current, request, tx)) {
          allMatched = false;
          break;
        }
        current = current.next;
      }
      if (!allMatched) continue;
      matched.push(rule.actions.id);
      current = rule;
      while (current) {
        updateState(current.actions.changes, tx);
        if (current.actions.skipAfter) skipUntil = current.actions.skipAfter;
        if (["deny", "block"].includes(current.actions.decision)) blocked = true;
        if (current.actions.status) status = current.actions.status;
        current = current.next;
      }
      if (blocked) break;
    }
    if (blocked) break;
  }
  const score = Number(tx.get("anomaly_score") ?? tx.get("inbound_anomaly_score") ?? 0);
  if (anomalyThreshold !== undefined && score >= anomalyThreshold) blocked = true;
  return { blocked, status: blocked ? status : 200, matched, score, tx: Object.fromEntries(tx) };
}
