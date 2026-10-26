import { compileExpression } from "../core/matcher.js";
import type { TrustedContext } from "../core/types.js";
import { canonicalPath } from "../http-boundary/index.js";
import { loadPolicy, type Policy, visit } from "../rule-ir/index.js";

/** Deliberately bounded admission profile for native handlers, including opaque WS/DNS bodies. */
export function validateHeaderPolicy(input: Policy, service: string): Policy {
  const policy = loadPolicy(input);
  for (const rule of policy.rules) {
    if (
      rule.service !== service ||
      rule.phase !== "request-headers" ||
      rule.then.action !== "block" ||
      rule.requests ||
      !["runtime-required", "edge-preferred"].includes(rule.placement)
    )
      throw new Error(
        "Automatic application requires stateless request-header block rules in the configured service",
      );
    visit(rule.when, (term) => {
      if (!["path", "method", "header", "query"].includes(term.field))
        throw new Error("Header policy requires observable path/method/header/query fields");
    });
  }
  return policy;
}

/** No proxy, body read, credential extraction or protocol substitution. Backend auth still runs. */
export function createHeaderPolicy(input: Policy, service: string) {
  const rules = validateHeaderPolicy(input, service).rules.map((rule) => ({
    rule,
    match: compileExpression(rule.when),
  }));
  return (request: Request, context: TrustedContext, now = Date.now()): string | undefined => {
    const url = new URL(request.url),
      path = canonicalPath(url.pathname);
    for (const { rule, match } of rules) {
      if (!rule.enabled || (rule.expiresAt && Date.parse(rule.expiresAt) <= now)) continue;
      if (match({ request, url, path, bodyText: "", context })) return rule.id;
    }
    return undefined;
  };
}
