# Cloudflare validation deployment / 隔离部署准备

This entry uses the real Worker APIs, supports optional origin/control service bindings, and is
tested in local workerd with HTTP, shared decision storage, media and actual WebSocket upgrades.
The control fixture in tests is memory-only; do not deploy it as a production authority. Provision
an authenticated persistent control API separately. SQLite authority can run on a private Node
host; the existing SQLite implementation cannot run inside a Worker.

```sh
npm ci
npm run check
npm run cloudflare:dry-run
```

The committed manifest intentionally has no production routes, no account identifier, disabled
workers.dev/preview URLs, and example-only destinations. It sends no Wrangler usage metrics.
Before deployment, copy this configuration to an ignored operator-local file and replace the
test host, isolated origin/control endpoints, exact routes and pinned policy. Add secrets with
`wrangler secret put ORIGIN_TOKEN --config <operator-config>` and likewise
`CONTROL_RUNTIME_TOKEN`, and `CLIENT_TOKEN` when using the example service-to-service identity.
Use different randomly generated secrets for all three. Do not use this machine identity as an
OAuth/session replacement; application integration can inject a real verifier through
`createCloudflareRuntime` from the `cloudflare-runtime` package export.

For Workers in the same zone, do not assume `fetch` can target an existing Worker Route. Use a
verified custom-domain path or an explicitly provisioned service binding. The runtime accepts
`ORIGIN_SERVICE` and `CONTROL_SERVICE` bindings; the example manifest provisions neither. Adding
a binding to the validation caller does not authorize modifying the existing origin Worker.

The operator chooses a dedicated test hostname/private caller and configures any needed route.
Until then this configuration is not publicly reachable. Publishing `api-shield-validation` without
a route does not put it in front of any existing service. A concrete deployment command, after
operator-local configuration and secret provisioning, is:

```sh
npx wrangler deploy --config <operator-config>
```

Never repoint a production domain as a test. Use isolated origin data for writes. Do not replay
production bodies/cookies to shadow endpoints. Validate read-only contracts, login/callback
assumptions, normal API responses, media seek/segments, socket reconnect, origin bypass rejection,
L1/L2, revocation and rollback. Release only when the operator-approved routing plan and these
results exist. Real Cloudflare account deployment has not been performed by the local tests.

中文：本配置只用于准备独立验证入口，不修改现有域名、Worker 身份、绑定或路由。旧业务须
持续可访问。严格源站隔离需要在正式切换阶段单独实施，不能在测试期间关闭旧入口。

References: [Routes](https://developers.cloudflare.com/workers/configuration/routing/routes/),
[service bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/).

## Scheduled cloud rule sources and CVE response / 云端定时维护

The real Cloudflare Worker receives HTTP/HTTPS traffic using its existing `fetch()` handler. The optional `scheduled()` handler runs every six hours through the checked-in Cron Trigger. It does not need a VPS or OpenResty.

Bind a **private** Cloudflare KV namespace as `SECURITY_KV` and set the following operator-managed bindings in your own Wrangler configuration:

- `RULE_SOURCE_URL`: HTTPS URL of a previously authorized Shield IR rule source, at most 128 KiB (no redirects).
- `RULE_REGRESSIONS`: JSON array of real, independently reviewed attack and legitimate simulation samples; every enabled source rule must be exercised before staging.
- `CVE_INVENTORY`: JSON CycloneDX, SPDX, npm lockfile, or explicit component inventory for up to 25 packages. This is operator-owned; a Worker cannot safely infer the software versions running on a private origin.
- `CVE_EMERGENCY_PATHS`: optional JSON object mapping exact component identities to *preapproved* isolation paths, for example `{"npm:widget":["/api/widget"]}`.

The scheduled task saves `candidates/rules/latest` and `candidates/cve/latest` in the private KV namespace with seven-day expiration. **These are reports, not active enforcement policies.** CVE candidates expire after one hour and may only propose feature isolation—not a guessed exploit signature or a virtual patch. They require independent regression, explicit operational approval, review and a separate deployment/rollback process before they can reach production. Existing runtime rules remain pinned in `POLICY`.

Workers receive already decrypted `Request` objects after Cloudflare performs the TLS handshake. For eligible zones, **Cloudflare Keyless SSL** is set up at the provider/TLS layer with a separately operated key server; no private key, packet-decryption logic or Keyless credential should be added to this Worker. Keyless SSL does not currently support TLS 1.3 and is an Enterprise add-on. Normal managed HTTPS is supported without Keyless SSL.

Validation manifest intentionally has no live routes or account identifiers. Nothing is deployed automatically to your Cloudflare account by a GitHub push.
