# Deployment / 部署

Cloud or third-party VPS origins and pinned rule imports can be managed from one YAML/JSON
inventory. See [source configuration](docs/SOURCE-CONFIG.md) and the runnable
[VPS configuration](examples/shield-vps.yaml). This is independent of provider-native WAF support.

For the Cloudflare validation Worker, service bindings, secrets and an unchanged-production-route
test sequence, see [deploy/cloudflare](deploy/cloudflare/README.md). Backend adoption follows
[BACKEND-STANDARD.md](BACKEND-STANDARD.md); media/WS/gRPC-Web require [protocol profiles](PROTOCOLS.md).

## Local execution

```sh
npm ci
npm run build
npm run dev
```

Use `curl.exe` in PowerShell if `curl` is aliased. The local origin/control/Shield bind loopback,
use real SQLite and require origin authentication. Set distinct 32+ character secrets before starting
to use control operations. Example PowerShell environment setup (generate your own values):

```powershell
$env:SHIELD_ORIGIN_TOKEN = 'replace-with-at-least-32-random-characters'
$env:SHIELD_ADMIN_TOKEN = 'replace-with-a-different-32-character-admin-secret'
$env:SHIELD_RUNTIME_TOKEN = 'replace-with-a-different-32-character-runtime-secret'
npm run dev
```

The string examples are placeholders, not production credentials. To run against your own HTTPS
origin, edit `examples/shield.yaml` and use:

```sh
node dist/packages/cli/main.js serve examples/shield.yaml
```

The CLI listener intentionally remains loopback-only. Put it behind a configured TLS/private
ingress. Its raw Node parser rejects ambiguous framing. Do not put an untrusted public proxy in
front and then trust its forwarded IP header: CLI grouping uses the actual socket peer. For true
client grouping, write a verified platform integration rather than trusting an arbitrary XFF.

## Control API and revocation

```sh
node dist/packages/cli/main.js control shield.db my-tenant 8790
# Offline administration of a known decision in the same authoritative file:
node dist/packages/cli/main.js revoke shield.db my-tenant decision-id
```

HTTP endpoints use `Authorization: Bearer ...`. Credentials bind tenant and role in server config;
request headers/query cannot select another tenant. Runtime role: GET generation, GET decision by
key, PUT newly detected decision. Admin role additionally lists/revokes decisions, reads audit,
saves policies and activates previous hashes. Control API routes:

| Route | Method | Meaning |
| --- | --- | --- |
| `/v1/generation` | GET | Current tenant epoch |
| `/v1/decisions?key=HASH` | GET | Active decision |
| `/v1/decisions` | PUT | `{decision, expectedGeneration}` CAS |
| `/v1/decisions` | GET | Admin bounded active list |
| `/v1/revoke` | POST | Admin `{id}` invalidates tenant generation |
| `/v1/policy` | POST/GET | Save validated policy / read active policy |
| `/v1/policy/activate` | POST | Activate saved `{hash}`; rollback uses previous hash |
| `/v1/audit?after=SEQ` | GET | Admin audit cursor, at most 1000 records |

Rotate credentials by restarting with a new credential mapping; encryption at rest, token lifecycle
and replicated authority HA are operator integrations. SQLite transactions are durable on one host,
not a cross-region database. Audit capacity fails mutations closed rather than growing forever;
archive records operationally. API list limits are explicit; do not treat a 1000-entry list as a full
arbitrary-size export. Policy activation requires explicit runtime reload/redeployment.

## Cross-cloud runtime artifacts

```sh
npm run check:edge
npx esbuild examples/cloud/cloudflare.ts --bundle --platform=browser --format=esm --target=es2022 --minify --outfile=artifacts/cloudflare.mjs
npx esbuild examples/cloud/netlify.ts --bundle --platform=browser --format=esm --target=es2022 --minify --outfile=artifacts/netlify.mjs
npx esbuild examples/cloud/vercel.ts --bundle --platform=browser --format=esm --target=es2022 --minify --outfile=artifacts/vercel.mjs
npx esbuild examples/cloud/esa.ts --bundle --platform=browser --format=esm --target=es2022 --minify --outfile=artifacts/esa.mjs
npx esbuild examples/cloud/edgeone.ts --bundle --platform=browser --format=esm --target=es2022 --minify --outfile=artifacts/edgeone.mjs
```

These commands produce tested portable artifacts; they do not provision a cloud project. Configure
`CloudEnvironment` from deployment secrets, a pinned policy and routes. Supply verified identity/IP
from the platform wrapper. Cloudflare has a Worker-style fetch export; the other entries expose
factory functions to bind to their platform triggers. Vercel may use its current default Node runtime;
the portable graph does not force Edge mode. Bind Netlify context.ip or Vercel's official ipAddress
helper only at the actual trusted platform boundary. ESA/EdgeOne raw client-IP bindings and trigger
formats require platform testing; these wrappers never guess them from arbitrary headers.

The Cloudflare validation manifest is locally verified; no deployment manifest is claimed ready for every account/platform.
Exact trigger wiring, secret binding formats, origin network isolation, quotas, package limits,
runtime API versions and platform raw-protocol behavior must be verified in a dedicated test
environment before live deployment. This repository has not deployed to any account.

For L0 use the typed adapter API in [CLOUD-ADAPTERS](CLOUD-ADAPTERS.md). Keep scoped cloud
credentials exclusively in an administrator/background process. CLI compatibility reporting is
read-only; actual application requires a reviewed plan hash. Timed native IP promotion is not enabled.

## Origin isolation

Verify the `x-shield-origin-auth` secret with constant-time comparison before application routing,
or use an equivalent verified platform/private-network identity. Reject missing/wrong tokens.
Restrict the origin network to the Shield ingress path, preserve proper TLS hostname verification,
and keep upstream PHP/Go/Node/Nginx patched. Merely setting a secret header at Shield cannot force
a separately managed origin to check it. Web fetch cannot portably configure certificate pinning,
raw HTTP parser policy, DNS pinning or client TLS certificates; enforce those outside this engine.

## Learning, feeds and performance

```sh
node dist/packages/cli/main.js learn observations.json model.json my-tenant ci,contract,operator
node dist/packages/cli/main.js learn examples/learning-observations.json artifacts/example-model.json local ci,contract,operator
node dist/packages/cli/main.js assess examples/inventory.json tests/fixtures/GO-2023-2102.json
npm run benchmark
```

Only locally approved sources may label observations verified. The learning command writes an
offline model/candidates file; it does not install or deploy it. Feed queries and community sharing
require explicit invocation/configuration. See their dedicated docs for evidence and consent gates.
The example observations are synthetic CLI fixtures, not a business baseline to install.
Benchmark output is `artifacts/benchmark.json`, with local latency/CPU/memory and cache counters;
cloud efficacy, cross-region latency and production false-positive rates are explicitly unavailable.

中文：先本机验收，再配置真实源站与最小权限密钥。构建成功和沙箱测试不等于真实平台已
部署。当前文档不会提供假装通用的一键云发布命令；各账号的触发器、可信客户端信息与源站
隔离需在授权测试环境验证后才能上线。完整缺口与后续验收见开发状态文档。
