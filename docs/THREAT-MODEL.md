# Threat model / 威胁模型

Assets: upstream data/auth boundaries, origin identity, tenant policy integrity, decision revocation,
cloud administrator authority, learning datasets and community trust. The adversary controls client
HTTP requests and can generate many IPs/keys; it cannot be assumed to possess verified platform
metadata, operator credentials or registered independent training sources.

Trust boundaries: protocol terminator → Web Request; verified platform/auth adapter → TrustedContext;
engine → fixed HTTPS origin; runtime-role token → tenant authority; operator plan → cloud management;
untrusted observations/feed records → offline evidence review; signed community reports → local
subscription policy. A signature authenticates a reporter, not the truth of its allegation.

| Threat | A: visible HTTP conditions / implemented | B: native protocol layer | C: upstream fix / gap |
| --- | --- | --- | --- |
| TE/CL, duplicate framing, malformed fields | Reject surviving ambiguity; local Node raw duplicate/framing checks | Original framing/obs-fold/H2/H3 downgrade must be validated by terminator | Patch all parsers; normalized Request cannot reconstruct raw bytes |
| Host/header injection | Exact public host, Host consistency, strip forwarding/hop headers, fixed origin | Validate original authority and duplicate field lines | Application must not trust forged host or forwarding metadata |
| Traversal/path normalization/auth bypass | Canonical path used for allowlist/match/proxy, reject ambiguous encodings and dot segments | Original raw target may normalize before function; local Node checks it first | Backend rewrites/aliases/auth routing still require contract tests and fixes |
| Double decode | Reject encoded percent/dot/separator path variants; bounded ordered rule decoding | Platform normalization may differ | Avoid backend re-decoding; maintain one canonical routing policy |
| Body/parser anomalies | Bounded read/deadline; strict UTF-8/JSON, duplicate keys/depth limits | Raw transfer frames and compressed transport limits belong to terminator | Multipart/compressed request body rejected; full native parsers planned |
| SSRF/unsafe proxy | Exact HTTPS origin allowlist, no redirect follow, no target from user query | Egress network restrictions, DNS policy | Operator controls DNS/egress; portable Web fetch has no DNS/certificate pinning |
| TLS identity | Normal HTTPS certificate verification, mandatory origin secret | mTLS/client certificate enforcement when supported | Cannot repair broken upstream TLS or server vulnerabilities in a request matcher |
| Resource exhaustion | Bounded request/response/cache/rate/model/feed state, timeout, concurrency, circuit breaker | DDoS/stream/reset floods before function need native layer | Patch protocol stacks; invocation cost already incurred is not zero |
| Learning poisoning | Candidate isolation, registered source quotas, source balancing, freeze/rollback, shadow/canary | External source identity and independent labels required | Colluding trusted sources can poison; no perfect zero-day detector claimed |
| Community false reports | Disabled defaults, signatures, organization quorum, warning lists, TTL/revoke | Identity/reputation/review operations required | In-memory hub is not a public, operated reputation service |

## Vendor-informed regression boundaries

- [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html) explains HTTP/1.1 framing and inconsistent
  parsing risks. Tests use loopback raw sockets to verify Node rejects TE/CL before the handler.
  This is a local parser regression, not a claim to inspect raw frames in every cloud.
- [Node June 2023 security release](https://nodejs.org/en/blog/vulnerability/june-2023-security-releases)
  includes CVE-2023-30589 parser leniency. Keep the terminating Node version patched; the local
  strict parser/raw checks are defense in depth, not a reproduction of the historical vulnerable runtime.
- [Go GO-2023-2102](https://pkg.go.dev/vuln/GO-2023-2102) concerns HTTP/2 reset/resource behavior.
  Its real advisory is an affected-version fixture. Request-level matching does not see stream resets;
  classify as protocol/upstream-required, not a precise JavaScript virtual patch.
- [PHP CVE-2024-4577 advisory](https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv)
  involves PHP-CGI and platform/configuration conditions. Do not infer exposure from a PHP banner;
  require verified runtime/configuration inventory and upgrade. No universal payload block is claimed.
- [Nginx security advisories](https://nginx.org/en/security_advisories.html) include module-specific
  memory and protocol defects. Module presence and fixed versions must be checked with the vendor;
  body-size bounds alone cannot be represented as a cure for memory corruption or TLS issues.

## Scheme coverage

Runtime rules can match HTTP-level preconditions where visible. Native WAF/terminators must handle
protocol conditions below the Request abstraction. Upgrades and secure upstream configuration remain
mandatory where no precise, independently verified HTTP mitigation exists. Unknown exposure stays
unknown. Neither CVE severity, AI output nor a mock passing provides high-confidence deployment evidence.

中文：A 类是能看到的请求条件；B 类是平台协议层才可见的条件；C 类必须修复后端组件。
本仓库没有运行历史易受攻击的 PHP/Go/Node/Nginx 镜像，没有完成各云原始 HTTP/2/3 回归，
也没有在生产目标发送载荷。未来隔离环境验证必须记录镜像哈希、版本、授权目标和无害正常
业务样本；可能触发崩溃/写入/内存破坏的复测不能默认在生产执行。
