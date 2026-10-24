# Security / 安全

This is a new security project without an independent audit or live-cloud certification. Use the
explicitly documented capability profile and keep the terminating proxy and upstream patched.

Report vulnerabilities through the repository's private security advisory feature once maintainers
enable it. If unavailable, open a minimal issue requesting a private contact without exploit data,
credentials, production addresses or customer payloads. No unmonitored security email is invented.

- Trust `TrustedContext` only when created by verified platform metadata/auth middleware. Runtime
  never treats a client header as proof of identity. CLI token authentication is a single configured
  API client; OIDC/JWT issuer/audience/session management is an application integration task.
- Origins must be fixed allowlisted HTTPS origins. Verify `x-shield-origin-auth` at the origin, use
  private ingress/firewall controls and rotate the secret. DNS ownership and egress filtering are
  operator responsibilities; Web fetch does not expose portable DNS pinning or mTLS controls.
- No redirects are followed upstream. Request hop-by-hop and untrusted forwarding headers are
  removed, and origin credentials are overwritten. Origin responses cannot expose Shield headers.
- Encoded path separators/dots/percent signs, traversal, semicolons, malformed encoding and
  non-NFC paths are rejected. Literal dot segments may already have disappeared in Web Request;
  the Node adapter checks the original target first. Platform termination must enforce raw framing.
- Compression and multipart are unsupported and rejected, rather than parsed incompletely.
  Duplicate JSON keys and excessive nesting are rejected. A response-size violation after streaming
  starts terminates the stream; the already-sent HTTP status cannot be replaced.
- Local rate limits are bounded per-instance windows, not globally consistent billing/quota limits.
  Saturated rate state fails closed. In-memory LRU is ephemeral and cannot prevent volumetric load
  before a function invocation. Regex uses RE2JS, pattern/input limits and no counted repetitions.
- Cached blocks are exact-request decisions, not inferred client-wide bans. Default cached-revoke
  staleness is bounded by polling (1s); strict 0ms mode is available. L2 failure re-evaluates all local
  rules by default; explicit `storageFailure: "closed"` is available. Mandatory checks never bypass.
  A rule match has default decision confidence 0.5 and native-sync status unsupported; it is not
  promoted as verified malicious activity merely because the request was blocked.
- Cloud publication requires exact-plan approval. Single-writer management is required where APIs
  lack atomic compare-and-swap. Mid-flight provider failures may leave partial native changes;
  read back and reconcile before retrying. Unrelated Vercel drafts are refused.
- Native timed bans/promotion, global revoke propagation, full parser compatibility and full
  community operations are not claimed. Community signal/hub state is experimental and in-memory;
  persisted feed checkpoints and trusted organization provisioning are required before any service.

Default telemetry and community uploads are off. IPs and even request fingerprints can be personal
or linkable data. Access, retention, notice and legal requirements are deployment-specific. No cloud
admin credentials belong in the runtime bundle or community center.

中文：安全报告请使用仓库私密漏洞通报，未启用时仅公开请求私密联系方式。不要公开凭证、
利用样本或客户数据。当前版本必须结合源站隔离、正确协议终止和及时升级组件使用。
不能将 Mock、沙箱通过、规则命中或配置回读当作生产防护证明。
