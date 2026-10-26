# Delivery status / 开发状态

This file is the capability ledger, updated through 2026.10.4. “Implemented” means executable code plus local tests;
“offline contract” is not live platform verification. Nothing has been published to a registry or
cloud account by this task.

0.1.2 adds [configuration-driven cloud/VPS origins and pinned rule imports](SOURCE-CONFIG.md),
with JSON Schema and CLI validation/import, plus a [inline VM terminal recordings](../README.md#actual-vm-recordings).
GitHub source/releases are published; npm registry publication and live cloud deployments are not claimed.

The original 56-test suite passed on Windows Node 22.23.1 and 24.19.0; later backend/protocol
extensions and workerd acceptance are recorded separately in [validation](VALIDATION.md).
Five portable runtime bundles and four native-management offline contracts passed. See
[validation evidence](VALIDATION.md) and [all changed files](FILES.md).

| Phase | Delivered | Remaining |
| --- | --- | --- |
| 0 | Research register, threat model, five-platform matrix, IR v1 Schema, ADRs, file-level plan | Provider/account-specific evidence and independent design review |
| 1 | Modular Web runtime, YAML/JSON validation, matching/block/detect/rate/score, safe proxy, L1, L2 interface/reference/HTTP path, persistent L3, TTL/CAS/revoke, events, CLI, protected local API, automated tests | Production audit and deployment-specific auth/origin/ingress verification; protocol/body features explicitly excluded by supported profile |
| 2 | Four real native API/SDK gateways, unified conservative compiler, hash-approved plans, readback, revoke, retry, drift/capacity checks; fifth adapter explicit unsupported; five portable runtime wrappers | Live tests for all accounts, native path/body semantic expansion, durable L0 outbox/expiry and promotion, drift metrics, platform trigger manifests, Netlify supported API |
| 3 | OSV + SBOM assessment, dedup, real advisory regression, CVE5/KEV/EPSS parsers/conditional fetch, audited regression-gated isolation workflow | Scheduled persistent orchestration, full range/lock support, vendor exposure/configuration assessment, precise virtual patches, native engine tests, patch attestation and safe withdrawal |
| 4 | OpenAPI discovery, source-isolated EWMA/type learning, anomaly scores/proposals, model freeze/rollback, shadow/canary state gates | Persistent training service, sequence/cardinality/cluster models, outcome collectors, signed model loading and automatic but preauthorized rollout integration |
| 5 | Separate installable converter project and strict main import contract; supported SecLang subset, partial CrowdSec, loss/metadata tests | Full semantic parsers, native Coraza/CrowdSec integrations and differential tests; independent repository/registry releases |
| 6 | Optional local signed hub/feed/subscriber logic; three consents, organization quorum, TTL/warnings/revoke/privacy tests | Independent durable service, identity reputation/anti-collusion operations, appeals/legal/retention, key rotation, sequence persistence, STIX/TAXII and L0 sync |

## Next work, with file-level acceptance criteria

The backend JSON standard, media streaming, experimental WS/gRPC-Web and Cloudflare validation
entry are implemented in `packages/backend-security/`, `packages/protocols/`,
`adapters/cloudflare/{runtime,websocket}.ts` and `deploy/cloudflare/`. These do not mean existing
applications have been migrated. Native gRPC, protobuf field rules, dynamic resource routes and
immediate revocation of established sockets remain unsupported/planned. Acceptance requires
real application auth/CSRF/storage contracts and isolated cloud tests before any production cutover.

1. `adapters/*/live.test.ts`, `examples/cloud/*`, `docs/provider-validation/`: create isolated
   test resources only after operator authorization; verify host/IP/auth metadata, real rule denial,
   active readback, expiry/revoke, POP convergence, quotas, secret handling and cleanup. Mark each
   provider live-verified only after recording these results.
2. `packages/control-plane/outbox.ts`, `decision-cache/providers/*`: durable leased jobs and
   conditional, bounded L2 adapters; test crashes, reordering, expired leases, tenant fairness,
   revoked-generation races and eventual-store gaps. Implement native expiry before timed L0 bans.
3. `packages/cloud-compiler/profiles/*`: expand one field at a time with raw/canonical path,
   duplicate header/query, transform, action, phase and rate-window differential tests against real
   providers; important unsupported conditions must still reject plans.
4. `packages/vulnerability/orchestrator/*`, `integrations/sbom/*`: persist feed checkpoints,
   workflow/audit state and evidence hashes; support vendor-specific version/configuration semantics.
   Require isolated upstream reproduction + normal traffic for a precise patch, and installed-patch
   proof before withdrawing mitigation. Do not infer a patch from a changed banner/version string.
5. `packages/learning/persistence.ts`, `sequence.ts`, `collector.ts`: versioned model store, trusted
   observation ingestion, bounded sequence/cardinality drift models and independent outcome labels.
   End-to-end acceptance: vetted data → proposal → verified shadow → authorized canary → rollback
   on false positive, with no ability to weaken authentication or origin isolation.
6. `api-shield-convert/src/native/*`, `tests/differential/*`: use pinned native Coraza/CrowdSec in
   isolated containers, retain source licenses and every condition. Test CRS chain/score/transform
   differences. Partial conversion must remain impossible to auto-import.
7. Separate `api-shield-community` repository/service: durable report/revocation/sequence store,
   key lifecycle, rate limits, reporter identity/reputation, privacy retention and appeals. Acceptance:
   no outbound traffic with any relevant consent off, restart-safe anti-replay, collusion/warning
   handling and false-positive withdrawal propagated to subscribers.

中文：后续阶段不是空目录占位；当前只交付有实现和测试的组件。上表缺口不得在 README、
发布说明或对外宣传中描述为已经具备的生产能力。Phase 1 支持范围之外的请求默认明确拒绝。

2026.10.1 replaces the previous custom recording console with actual existing WSL2 desktop/xterm captures, removes its standalone demo document, adopts YYYY.M.N versioning, fixes configured CLI Host handling and Linux npm-bin symlink entry execution, and removes the converter’s unnecessary Core dependency. No existing web site files are changed by these recording updates.

## 2026.10.4: ShieldWeave

The public project is renamed ShieldWeave. Hosting is independent of origin location:
local servers, VPS and containers use the Node entry point; cloud adapters use the same Web runtime.
Added a multi-stage non-root Docker image, restricted Compose profile, TLS ingress example,
systemd runtime and hourly rule synchronization timer. A real process test verifies origin auth,
forwarding, rule/L1 blocks and L2 persistence across restart. Container execution remains unverified
on the current Windows host (no Docker engine).

Public/private HTTPS sources now support environment-only read credentials and an explicit
serial background polling daemon. Bounded SQLite candidates retain provenance, conversion status,
real-runtime attack/legitimate regression evidence and redacted audit attempts. Active policy is
never changed by synchronization. Private authentication is Mock-tested; no operator private rule
repository has been configured. Full CRS and arbitrary third-party formats still require supported
external converters and differential testing; downloaded bytes are not claimed as equivalent protection.
