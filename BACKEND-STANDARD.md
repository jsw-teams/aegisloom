# Backend Security Standard v1 / 后端统一安全标准

This is a shared security contract across platforms and protocols. Compliance requires evidence
from the actual application and ingress. A manifest passing `backend-check` is configuration
validation, not proof of compliance. Existing applications have not been migrated by publishing
this project. This project is independent of Cloudflare's commercial API Shield product.

这是一套跨平台、按协议分型的共同标准。不能以 WAF 代替业务授权，也不能把通过配置检查
当作现网已完成整改。现有服务的登录、对象所有权、存储兼容及域名必须逐项回归验证。

| ID | Required behavior / 必须满足 | Current enforcement and acceptance |
| --- | --- | --- |
| B01 | TLS and origin isolation / TLS 与源站隔离 | Fixed HTTPS allowlist; independent 32+ character origin secret, optional two-key rotation. Reject direct requests lacking proof. Private network/service bindings preferred; remove public bypass only after a separately authorized cutover. |
| B02 | Verified identity / 可信身份 | Explicit public/bearer/session route declaration. Real authentication callback; never accept identity, tenant or client IP from arbitrary forwarded headers. Bearer syntax alone is not verification. |
| B03 | Object authorization / 对象级授权 | Application callback verifies operation, tenant, owner and current authoritative state before every private operation. Shield cannot infer object ownership. |
| B04 | CSRF and browser origins / CSRF 与浏览器来源 | Session mutations require an exact configured public browser origin plus token verification. WebSockets require exact browser-origin allowlist; originless clients need a distinct explicit policy. CORS never grants authentication. |
| B05 | Explicit boundaries / 显式请求边界 | Exact routes and methods; reject ambiguities, duplicate JSON keys, unsupported encodings; bound bytes, headers, time and concurrency. Unknown routes do not reach business handlers. |
| B06 | Bounded streaming / 流式资源限制 | Per-protocol header, idle, byte and message limits; client cancellation and backpressure. No fixed short total timeout for progressing media. Native-frame gaps must be reported. |
| B07 | Sensitive output / 敏感响应 | JSON guard forces no-store/nosniff; response header allowlist; cookies require Secure, HttpOnly and explicit SameSite. Generic errors carry generated request IDs, never stack traces or credentials. |
| B08 | Audit privacy / 审计与隐私 | Default event contains only scope, request ID, outcome/status and duration. No cookie, token, URL, query, body, account or IP. Application logs need the same review; external uploads remain opt-in. |
| B09 | Storage and concurrency / 存储一致性 | Authoritative tenant isolation and conditional generations. Apply ownership checks atomically with writes. Persistent storage required in production; memory fixtures are not production stores. |
| B10 | Reversible release / 可撤销发布 | Pin code/rules, regression-test normal and rejected cases, shadow/canary before enforcement; preserve rollback. No cloud management calls in request path. |

## Executable JSON API profile

`packages/backend-security/` exports a portable Web API middleware, origin verifier and strict
policy validator through `@jsw-teams/shieldweave/backend`. The JSON guard enforces B01–B08
within its declared profile, with B02/B03/B04 verification delegated to mandatory application
callbacks. It caps request bytes at 1 MiB, response bytes at 1 MiB, total API work at 30 seconds
and concurrent admitted operations at 256. Deployment settings can be stricter.

```sh
npm run build
node dist/packages/cli/main.js backend-check examples/backend-policy.yaml
```

Import `createBackendGuard` and supply `policy`, `originTokens`, `authenticate`, `authorize`,
`verifyCsrf` and `handle`. The authentication callback returns a verified `{subject}` or undefined;
authorization returns a boolean; CSRF verifies a session-bound anti-CSRF token. The business
handler receives a fresh bounded request and trusted context including the validated JSON value.
Callbacks see a cancellation signal; a callback ignoring cancellation retains its concurrency
slot until it settles, preventing unlimited admission after timeouts. Such a faulty callback can
exhaust the bounded pool and requires operator recovery. This does not make arbitrary callback
code safe or automatically roll back business writes after a client timeout.

`sessionOrigins` records the actual approved browser origins, independently of the private backend
`hosts`. Proxying to a different upstream hostname must not cause the backend to infer a browser
origin from an arbitrary forwarded-host header. Cross-origin browser access needs its own reviewed
CORS/credential policy; this JSON middleware does not emit permissive CORS grants.

Only exact JSON API routes belong inside this middleware. OAuth redirects, embeddable HTML,
public cacheable assets, large uploads, media and sockets require their own profile and tests.
Use `createOriginVerifier` independently when the full JSON profile does not fit an application.
Protocol adapters may import the shared boundary, bounded body reader and strict JSON parser
from `@jsw-teams/shieldweave/http-boundary`; do not duplicate these parsers per business.
The secret proves the gateway's possession of a credential; it does not attest that an arbitrary
caller ran a particular policy. Protect the credential and network path accordingly.

## Application adoption / 业务接入

Keep platform adapters thin; put shared authentication, authorization and service policy outside
them. Preserve existing session/signing keys, object IDs, storage, consent contracts, public static
routing and callbacks. Do not replace application authentication with the example machine token.

For each service, record its route/profile inventory, public versus private operations, auth and
CSRF mechanism, origin isolation proof, storage consistency, normal and rejected sample results,
stream/message resource limits and rollback version. Missing evidence means **unverified**, not
compliant. Scan no production target and modify no live route as part of this acceptance process.

中文：先在隔离入口完成同一套验收，再分批接入。静态站点不增加业务后端；后端仍由原业务
维护。流媒体、WebSocket、gRPC-Web 的协议要求参见 [PROTOCOLS.md](PROTOCOLS.md)。

References: [OWASP REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html),
[OWASP Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
