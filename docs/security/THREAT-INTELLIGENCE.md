# Community intelligence / 社区威胁情报

All three independent consent flags default false:

```ts
{ upload: false, subscribe: false, autoBlock: false }
```

Subscribing does not authorize uploading or enforcement. Uploading does not authorize downstream
blocking. No component is automatically attached to the runtime. An explicitly constructed
`CommunitySubscriber` can be passed to `createShield({ community: subscriber, ... })`; its own
subscribe/autoBlock checks remain mandatory. It receives only verified client IPs from the runtime.

The experimental module includes Ed25519 signed minimal reports and full versioned snapshots,
strict report fields (extra cookies/headers/body are rejected), bounded memory, a minimum of three
pre-provisioned independent organizations, per-organization deduplication, quorum TTL,
warning-list exclusions, monotonically increasing subscriber checkpoints and explicit revocation.
IPv4 public addresses only; IPv6 reporting/enforcement is unsupported. Confidence and observations
are prerequisites, not sufficient proof. Reports from multiple accounts in one organization count
as one independent source.
Public verification keys must be extractable Ed25519 keys (public bytes are not secrets). A signing
key fingerprint cannot count as multiple organizations, even when the registry mistakenly assigns
the same public key under different organization labels.

`uploadSignal` only sends with upload consent, an allowlisted HTTPS destination, valid minimal
signal and no redirects. No Cookie, Authorization, API key, private URL or request body is included.
The hub uses configured public keys/organizations, not self-declared organization IDs from reports.
No centralized cloud administrator key is used.

This is **not a deployed community service**. Hub reports, revocations and signing sequence are
currently in-memory; production persistence, signer key rotation, durable monotonic sequences,
reporter onboarding/reputation, independent-source identity verification, report review, appeal,
jurisdiction/privacy notices, deletion/retention operations, STIX/TAXII and automatic L0 sync remain
planned. Persist subscriber checkpoints across restarts and provision current public-network/CDN/
NAT warning lists before any opt-in enforcement. Hub snapshots alone are not absolute truth.

Quorum and signatures do not prevent colluding organizations or validate all evidence. A deployment
must review its acceptable false-positive risk and retain local override/revocation authority. The
module tests prove disabled defaults, privacy field rejection, same-organization deduplication,
signature rejection, stale-feed rejection, expiry, warnings and false-positive revocation.

中文：社区默认完全关闭，没有启动公共服务，没有上传 IP。开关必须单独授权，不能用订阅
替代上传授权。当前仅是可测试的本地协议与信誉门控组件；真实社区运营、隐私和申诉流程
仍然缺失，不能直接作为全网自动封禁服务使用。
