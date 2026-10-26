# Cloud adapters / 云平台联动

Research date: 2026-10-24. Quotas/entitlements are not hardcoded promises; supply the actual target
quota. Every adapter exposes capabilities, compile, plan, apply, readback, revoke and reconcile.
Unavailable methods throw `UnsupportedCapability`; no simulated provider is shipped as a real one.

| Platform | Runtime entry | Native lifecycle code | Verification |
| --- | --- | --- | --- |
| Cloudflare | `examples/cloud/cloudflare.ts` | Rulesets REST for an existing zone custom phase entrypoint; per-rule create/update/delete | Offline HTTP contract + browser/sandbox; no live account |
| Netlify | `examples/cloud/netlify.ts` | Explicitly unsupported pending a verified public lifecycle API | Capability refusal contract + browser/sandbox |
| Vercel | `examples/cloud/vercel.ts` | Config GET/PATCH, draft activation, active GET | Offline REST + pinned official SDK schema + browser/sandbox |
| ESA | `examples/cloud/esa.ts` | Official ESA SDK List/Create/Update/DeleteWafRule, version 2024-09-10 | Offline SDK/request contract + browser/sandbox |
| EdgeOne | `examples/cloud/edgeone.ts` | Official teo REST Describe/ModifySecurityPolicy + Web Crypto TC3, version 2022-09-01 | Signer differential against official SDK; offline request/preservation contract + browser/sandbox |

The runtime can also be embedded on other hosts exposing Web Request/Response/fetch/Web Crypto.
AWS/Azure/Fastly/Deno-specific deployment wrappers and native enforcement are not implemented.

## Unified compilation

The same validated IR feeds L1 and L0. Native profile v1 supports AND/OR/NOT of uppercase method
equality and canonical IPv4 equality, with block actions. Native detection/log action ordering is
not yet proven equivalent and remains runtime-only. Vercel DNF expansion
is capped. Regex, decoded query, duplicate header interpretation, application identity, path
canonicalization, score accumulation, body parsing and local frequency windows do **not** silently
translate. They produce runtime-only/unsupported compatibility reports. Native expiry is refused
until a durable expiration controller exists. An edge-required mismatch prevents plan generation.

This conservative profile is not full platform capability coverage. A platform may support a field
whose equivalence to this runtime has not been established. Challenge is not an alias for block.
Unknown capacity, entitlement or missing phase configuration must be corrected before publication.
Cloudflare non-Enterprise detection logging is not assumed. ESA site version publishing and EdgeOne
template binding are operator-managed and not claimed as automated here.

## Real API use, with explicit plan authorization

```ts
import { CloudflareGateway, createCloudflareAdapter } from '@jsw-teams/shieldweave/cloud';
const gateway = new CloudflareGateway(zoneId, existingRulesetId, scopedToken);
const adapter = createCloudflareAdapter({ tenant, service: 'api', maxRules: actualQuota, gateway });
const plan = await adapter.plan(validatedPolicy); // read-only
// Review/persist plan and obtain approval for this exact hash and target.
await adapter.apply(plan, { planHash: approvedHash, approvedBy: operatorId, expiresAt });
await adapter.reconcile(plan);
const removal = await adapter.revoke(ruleId); // removal PLAN, still read-only
// Applying removal requires the same concrete-plan approval gate.
```

ESA uses `createEsaSdkGateway`, EdgeOne `createEdgeOneGateway`, and Vercel `VercelGateway`.
Parameters are typed in their adapter files; credentials are never passed to the edge runtime.
`syncCloud` re-plans after failures, audits attempts and invokes an authorization callback for each
new plan hash. It is a bounded background operation, not a durable job scheduler. No native IP
promotion is automatically driven by a single runtime hit.

Deployment plans preserve unowned rules and use tenant/service namespaces. Readback mismatch means
**not confirmed**, even after a successful write. APIs without atomic CAS require an exclusive
configuration writer; a read-before-write drift check cannot solve all concurrent writers. API
readback confirms configuration only, not global edge propagation or traffic protection. Provider
errors during a batch can leave partial state; inspect/re-plan rather than blindly replaying creates.

Vercel refuses a distinct existing draft to avoid publishing somebody else's work. SDK schema review
showed `rules.update` was not a content-replacement contract in the pinned version, so content
replacement uses documented remove/insert followed by explicit draft activation. A failure leaving
a draft may require operator recovery; automatic ownership recovery of drafts is planned.

## Official references

- [Cloudflare custom rule creation](https://developers.cloudflare.com/waf/custom-rules/create-api/)
  and [availability](https://developers.cloudflare.com/waf/custom-rules/): zone custom phase, plan-dependent actions and quotas.
- [Netlify Traffic Rules](https://docs.netlify.com/manage/security/secure-access-to-sites/traffic-rules/)
  and [public OpenAPI](https://open-api.netlify.com/): IP/geography controls; no equivalent custom-WAF API was verified in this review.
- [Vercel Firewall REST API](https://vercel.com/docs/vercel-firewall/firewall-api)
  and [configuration endpoint](https://vercel.com/docs/rest-api/security/update-firewall-configuration).
- [ESA CreateWafRule](https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/api-esa-2024-09-10-createwafrule)
  and [field semantics](https://help.aliyun.com/en/edge-security-acceleration/esa/user-guide/phase-list).
- [EdgeOne ModifySecurityPolicy](https://edgeone.ai/document/50950): CustomRules replacement, template targeting and API version.
- [Tencent TC3 signing](https://intl.cloud.tencent.com/document/product/1220/63385): canonical POST JSON request signing. The implementation is compared offline with the official SDK; the SDK remains a development-only oracle.

中文：目前五家都有运行时包装器，四家有真实管理接口代码；全都尚未经过真实账号验证。
能力矩阵区分“平台本身可能支持”“本编译器证明可转换”“线上验证成功”，不能互相替代。
