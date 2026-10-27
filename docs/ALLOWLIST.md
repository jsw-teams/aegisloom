# EdgeShield user-managed allowlist / 用户自主白名单

The deployment owner controls all entries. No mandatory maximum number of entries, mandatory expiration, required ticket, or restricted bypass scope is imposed by EdgeShield. An empty configuration means **no exceptions**. EdgeShield does not generate or silently apply allowlist entries.

Optional scope filters: `path`, `pathPrefix`, `methods`, `identity`, `verifiedClientIp`, `cidrs`, `ruleIds`, and `expiresAt`. Choose `skip: [rules]` to exempt the rule engine, `skip: [community]` for community intelligence, or both. Omitting `ruleIds` or setting it to `["*"]` exempts all WAF rules in the selected scope; omitting every selector creates a global exemption at your direction.

**Example operator-owned JSON:**

```json
[
  {
    "id": "owner-approved-false-positive",
    "skip": ["rules"],
    "ruleIds": ["query-union-select"],
    "pathPrefix": "/api/report",
    "methods": ["GET"],
    "cidrs": ["192.0.2.0/24"],
    "reason": "False positive confirmed by operator",
    "expiresAt": "2026-11-10T00:00:00Z"
  }
]
```

On Node/VPS set `allowlistFile: ./allowlist.json` in the existing server YAML. Cloudflare Worker accepts the JSON value as an operator-managed `ALLOWLIST` binding. The configuration is loaded at runtime startup; on Node, a config reload updates it. Store private identities and CIDRs in private configuration, not the public repository.

**What it bypasses:** the selected WAF rule matches, including cached L1/L2 decisions, and optionally community-intelligence blocks. **What it does not bypass:** invalid HTTP syntax, authentication requirements, route/method authorization, tenant checks, request size limits or origin access credentials. These layers are separate from the WAF.

The allowlist is entirely yours. A global permanent bypass is supported if you explicitly configure it, but it effectively disables WAF decisions for matching traffic. Only trust IP addresses verified by your actual ingress; attacker-supplied X-Forwarded-For is not an identity. The `operator-allowlist` event is emitted for skipped rule matches.

中文：白名单全部由部署者自己配置，可全局、针对规则、接口、身份、方法或可信 IP/CIDR 豁免，可选过期时间，不设强制期限。EdgeShield 不自动生成白名单，也不会借安全建议限制用户的选择。
