# Research register / 调研记录

Reviewed 2026-10-24; URLs are primary project/vendor references. Limits must be rechecked before a
provider rollout. No plan feature or endpoint is inferred from another vendor's API shape.

| Ecosystem | Source | Design implication |
| --- | --- | --- |
| ModSecurity/Coraza | [Coraza SecLang](https://www.coraza.io/docs/seclang/), [directives](https://www.coraza.io/docs/seclang/directives/), [actions](https://www.coraza.io/docs/seclang/actions/) | Chains, phases, state and transformations require semantic analysis; no arbitrary exec in Shield |
| CRS | [Official CRS docs](https://coreruleset.org/docs/) | A collection for compatible engines, not one block predicate; independent source licensing/version checks |
| CrowdSec | [AppSec syntax](https://doc.crowdsec.net/docs/next/appsec/rules_syntax/) | In-band alerts/out-band events and scenario remediation differ from inline block |
| Sigma | [Specification](https://github.com/SigmaHQ/sigma-specification) | Log-event detections need event pipeline, not forced HTTP deny rules |
| Nuclei | [Template documentation](https://docs.projectdiscovery.io/templates/introduction) | Active tests are not passive WAF conditions; execution requires separate target authorization |
| Suricata | [HTTP keywords](https://docs.suricata.io/en/latest/rules/http-keywords.html) | Protocol buffers and network visibility exceed normalized Request; no lossy one-to-one compiler |
| Regex | [RE2JS](https://github.com/le0pard/re2js) | Portable non-backtracking matching with bounded compile/input profile |
| Intelligence | [OSV schema/API](https://ossf.github.io/osv-schema/), [query](https://google.github.io/osv.dev/post-v1-query/) | Unsupported ecosystem/range semantics are unknown, not unaffected |

Provider research and plan restrictions: [CLOUD-ADAPTERS.md](../CLOUD-ADAPTERS.md). Protocol/vendor
advisories and observable gaps: [THREAT-MODEL.md](THREAT-MODEL.md). Installed official ESA, EdgeOne
and Vercel SDK declarations/schemas were additionally checked against implemented request shapes.
The SDKs are pinned in the lockfile. Tencent's SDK has a vulnerable uuid range; it is used only as a
development-time signing oracle, with a CJS-compatible uuid 11.1.1 override for local tests. Production
EdgeOne management uses the documented TC3 REST algorithm and does not depend on that SDK or rely
on a consumer inheriting npm overrides. npm audit is part of CI and package verification.

Follow-up questions requiring actual accounts/environments:

1. Exact plan quota/actions and managed/custom-rule ordering for each target.
2. Runtime trigger and verified IP/identity metadata on ESA/EdgeOne, and raw normalization before
   invoking each provider's function.
3. Active configuration convergence across POPs; observed revoke and rule-effect time.
4. ESA version-managed publishing, EdgeOne template binding and Vercel draft recovery concurrency.
5. Whether Netlify offers a documented, supported lifecycle API suitable for custom WAF compilation.
6. Real backend parser/routing/body semantics for each protected deployment.

2026-10-24 follow-up: [Workers WebSockets](https://developers.cloudflare.com/workers/runtime-apis/websockets/),
[service bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/),
[same-zone Routes](https://developers.cloudflare.com/workers/configuration/routing/routes/),
[gRPC-Web specification](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md), and
[Cloudflare's August 2026 gRPC announcement](https://blog.cloudflare.com/grpc-workers/).
The announcement describes private-beta translation/Containers paths; account availability is
unverified. Local workerd exposed an actual unsupported redirect mode in the HTTP decision client;
all portable remote calls now use manual redirect handling and reject non-success statuses.
Miniflare is pinned to the beta required by the pinned Wrangler; its undici dependency is overridden
to 7.30.1 for published security fixes and is exercised in real workerd tests. All dependency audits
must remain enabled; the override is development-only, not a consumer runtime requirement.

中文：调研结果用于限制实现边界，不把“某平台有 WAF”推导为“所有套餐都能调用某接口”。
这份记录区分官方支持、SDK 契约和真实线上验证；第三项目前没有任何账号结果。
