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

## GitHub Actions maintenance, not Worker Cron / 使用 GitHub Actions 维护规则

The Worker contains **only** the `fetch()` request handler. No Worker `scheduled()` handler, Cron Trigger, or KV maintenance binding is required.
`.github/workflows/rules-maintenance.yml` runs by default every six hours and when reviewed `rules/` inputs change. After source, license, scope, and attack/legitimate regressions pass, GitHub Actions commits `rules/active.json` and `rules/cve-candidates.json` to the repository. The Action does not update the deployed Worker POLICY, cloud routing or credentials. See [rules/README.md](../../rules/README.md).

Cloudflare terminates TLS and gives the Worker an already decrypted HTTP `Request` under its trust boundary. If the zone uses Keyless SSL, Cloudflare performs the remote-key operation at its TLS layer; no private keys or arbitrary TLS decryption switches belong inside the Worker. Eligibility and TLS version support must be verified with Cloudflare.

Production rule updates require a separate operator-approved rollout and rollback. The scheduled OSV report may recommend bounded feature isolation, but it never publishes CVE block rules automatically.
