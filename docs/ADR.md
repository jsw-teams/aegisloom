# Architecture decisions / 架构决策

## ADR-001: Portable execution graph

Use TypeScript/ESM and standard Web APIs for matching/proxying/crypto. Node is a local/control
transport, not an engine dependency. Cloud SDKs live under adapters. This permits browser-target
bundles for all five named platforms and ordinary Node hosting. A provider's trigger API and trust
metadata remain adapter-specific. Portability does not mean identical protocol visibility.

## ADR-002: Static Schema validation and bounded RE2

JSON Schema is the versioned rule contract. AJV compiles it at development/build time into a
checked-in validator. No runtime new Function/eval is needed. YAML aliases, duplicate keys, unknown
keys and excessive tree complexity are refused before matching. RE2JS avoids JavaScript regex
backtracking and is constrained by pattern/input/rule bounds. Counted repetition is excluded from
the initial profile to reduce compilation-state expansion. No arbitrary scripts are accepted.

## ADR-003: Narrow decision scope, explicit consistency

Cache exact-request decisions keyed by tenant, canonical policy hash, request URL/method/headers,
body hash and trusted identity context. Do not escalate a request signature into an IP ban.
Authority writes are conditional on a tenant epoch. Revocation advances the epoch and makes stale
writes/caches invalid; local entries are never permanent. Epoch polling defaults to 1s, configurable
to strict per-request checks. A control outage causes cache discard and full local evaluation by
default. Explicit closed mode is available; mandatory boundary/identity checks always remain active.

## ADR-004: Durable local authority before distributed backends

SQLite WAL with immediate transactions implements an auditable, restart-safe single-node authority.
The Web engine sees only DecisionStore. An authenticated HTTP client enables a real remote authority;
an in-memory bounded store is explicitly a process-local test/reference. Eventual KV is not falsely
advertised as linearizable CAS. Production L2 providers, replication and failover require separate
implementations/contracts rather than unsafe optimistic overwrites.

## ADR-005: Reject semantic cloud losses

Capabilities, compiler reports and plan approval precede external mutation. A namespace and baseline
hash preserve unowned configuration; active readback is required after publication. Native profile
v1 deliberately handles fewer fields than providers expose because normalized path, repeated header,
query decode, identity, regex, stage and rate-counter equivalence must be proven. Important
unsupported rules fail publication. Without atomic provider CAS, require one configuration writer.
Quota inputs are explicit; plan price or free-tier limits never justify dropping conditions.

## ADR-006: Offline, explainable adaptive proposals

Learning uses registered trusted sources, balanced source quotas, EWMA and parameter type sets.
Candidates are isolated; anomalous samples pause their learning path. Versions can freeze/rollback.
Shadow/canary gates require independently labeled outcomes and never alter origin or authentication
requirements. No LLM, model download, active production scan or automatic self-promotion is required.

## ADR-007: Conservative vulnerability response

OSV package coordinates and supported range types are evaluated exactly; unsupported semantics are
unknown. CVE CNA versions and KEV/EPSS are evidence/priority inputs, not automatic exploit proofs.
Only declared, preauthorized temporary feature isolation is generated now. Precise virtual patches,
installed-patch verification and withdrawal require independent evidence and remain future work.

## ADR-008: Independent ecosystem and privacy consent

The converter has its own package/lock/tests and no core-source imports. Provenance, source version,
license/hash and semantic limitations survive conversion. Complex CRS/AppSec rules are better served
by future native engines. Community upload, subscribe and execute grants are separate and disabled.
Signed quorum signals remain local optional risk input; public service operations are not implied.

中文：这些决策优先保证安全可验证性、可移植性和明确边界，不为减少函数调用而删检测条件。
可运行的持久化、缓存撤销与规则闭环先于无法证明等价的“全平台一键同步”。
