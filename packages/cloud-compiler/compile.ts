import type { Expression, Rule } from "../rule-ir/index.js";
import type { Capability, CompiledRule, Provider } from "./types.js";

function leaf(expr: Expression, provider: Provider): string {
  if ("all" in expr) return `(${expr.all.map((e) => leaf(e, provider)).join(" and ")})`;
  if ("any" in expr) return `(${expr.any.map((e) => leaf(e, provider)).join(" or ")})`;
  if ("not" in expr) return `(not ${leaf(expr.not, provider)})`;
  if (expr.transforms?.length || expr.op !== "eq")
    throw new Error(
      "Only scalar equality without transforms is proven equivalent in this L0 profile",
    );
  if (expr.field === "method") {
    if (typeof expr.value !== "string" || !/^[A-Z]{1,20}$/.test(expr.value))
      throw new Error("Method must be an uppercase token");
    return provider === "edgeone"
      ? `\${http.request.method} in ['${expr.value}']`
      : `http.request.method eq ${JSON.stringify(expr.value)}`;
  }
  if (expr.field === "client.ip") {
    if (
      typeof expr.value !== "string" ||
      !/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(expr.value) ||
      expr.value.split(".").some((s) => Number(s) > 255)
    )
      throw new Error("Only canonical IPv4 equality is supported by this compiler profile");
    return provider === "edgeone"
      ? `\${http.request.ip} in ['${expr.value}']`
      : `ip.src eq ${expr.value}`;
  }
  throw new Error(
    `${expr.field}: normalization, identity, multiplicity or observability equivalence unverified; retain runtime enforcement`,
  );
}

/** Bounded DNF compilation for Vercel; NOT preserves leaf semantics via neg. */
function dnf(expr: Expression, negate = false): Record<string, unknown>[][] {
  if ("not" in expr) return dnf(expr.not, !negate);
  if ("all" in expr || "any" in expr) {
    const terms = "all" in expr ? expr.all : expr.any;
    const conjunction = "all" in expr !== negate;
    let result: Record<string, unknown>[][] = conjunction ? [[]] : [];
    for (const term of terms) {
      const group = dnf(term, negate);
      if (conjunction) {
        if (result.length * group.length > 32) throw new Error("DNF expansion exceeds 32 groups");
        result = result.flatMap((a) => group.map((b) => [...a, ...b]));
      } else result.push(...group);
      if (result.length > 32 || result.some((g) => g.length > 32))
        throw new Error("Vercel condition capacity exceeded");
    }
    return result;
  }
  // Validate using the same semantic restrictions as the expression platforms.
  leaf(expr, "cloudflare");
  return [
    [
      {
        type: expr.field === "method" ? "method" : "ip_address",
        op: "eq",
        value: expr.value,
        neg: negate,
      },
    ],
  ];
}
export function compileRule(rule: Rule, cap: Capability): CompiledRule {
  const errors: string[] = [];
  if (!cap.management)
    errors.push("Public management API with required semantics has not been verified");
  if (rule.placement === "upstream-required") errors.push("Must be repaired/enforced upstream");
  if (rule.phase !== "request-headers") errors.push(`Unsupported phase ${rule.phase}`);
  if (rule.requests)
    errors.push("Runtime fixed windows are not equivalent to platform rate counters");
  if (rule.then.score) errors.push("Anomaly score accumulation is runtime-only");
  if (!cap.actions.includes(rule.then.action))
    errors.push(`Unsupported action ${rule.then.action} for configured entitlement`);
  if (rule.then.action !== "block")
    errors.push("Only block action ordering is verified in native profile v1");
  if (rule.expiresAt)
    errors.push(
      "Native expiry not implemented; cannot safely promise timed revocation without a durable scheduler",
    );
  if (errors.length)
    return {
      ruleId: rule.id,
      status: rule.placement === "edge-required" ? "unsupported" : "runtime-only",
      errors,
    };
  try {
    let payload: Record<string, unknown>;
    if (cap.provider === "vercel")
      payload = {
        active: rule.enabled,
        conditionGroup: dnf(rule.when).map((conditions) => ({ conditions })),
        action: { mitigate: { action: rule.then.action === "block" ? "deny" : "log" } },
      };
    else {
      const expression = leaf(rule.when, cap.provider);
      if (expression.length > 4096) throw new Error("Expression capacity exceeded");
      if (cap.provider === "cloudflare")
        payload = {
          expression,
          action: rule.then.action === "block" ? "block" : "log",
          enabled: rule.enabled,
        };
      else if (cap.provider === "esa")
        payload = {
          expression,
          action: rule.then.action === "block" ? "deny" : "monitor",
          status: rule.enabled ? "on" : "off",
        };
      else
        payload = {
          Condition: expression,
          Action: { Name: rule.then.action === "block" ? "Deny" : "Monitor" },
          Enabled: rule.enabled ? "on" : "off",
          RuleType: "PreciseMatchRule",
          Priority: 0,
        };
    }
    return { ruleId: rule.id, status: "exact", errors: [], payload };
  } catch (error) {
    return {
      ruleId: rule.id,
      status: rule.placement === "edge-required" ? "unsupported" : "runtime-only",
      errors: [(error as Error).message],
    };
  }
}
