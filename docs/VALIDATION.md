# Validation evidence / 验证记录

## ShieldWeave 2026.10.4, 2026-10-26

Windows Node 24.19.0: npm run check passed 87 main tests, 3 converter tests,
typecheck/lint/schema freshness/build, all five Web runtime sandbox bundles,
installed-tarball imports/audit and a separate-process origin/cache/revocation smoke.
After the final source-regression and export updates, typecheck/lint and all 7 source-sync /
standalone tests passed again; the built CLI exported a verified candidate without activation.
Fresh npm run audit: zero vulnerabilities.

A real unauthenticated public GitHub Contents fetch imported this project's example policy,
passed two real-runtime regression samples, persisted a verified candidate and reported not-due
on the next scheduled invocation. This is an example rule-source transport test, not proof of
third-party CRS coverage. Private source authorization, redaction, failure preservation, capacity,
conversion status and poisoning/false-positive regression gates are Mock-tested.
No operator private rule source was supplied; no private live synchronization is claimed.

The standalone test launches the actual CLI against a real socket origin. It checks authenticated
forwarding, spoofed forwarding-header removal, rule -> L1 blocking and persistent L2 recovery
after process restart. Docker/Caddy/systemd profiles were reviewed against official documentation;
no container engine is installed here, so container and Linux-service execution remain unverified.
Native gRPC and Node WebSocket upgrade support are not claimed.


## Configured sources and video, 2026-10-25

Windows Node 24.19.0: `npm run check` passed 76 main tests, 3 independent converter tests,
schema freshness, typecheck/lint, build, five browser-target sandbox executions, installed-tarball
verification/audit and separate-process smoke. New tests validate configured cloud/VPS HTTPS
origins and secret references, source pins/licenses/service scope, bounded local/remote imports,
redirect/compression refusal and configuration-relative upstream selection.

The previous 0.1.2 custom-console recording has been superseded by the actual VM terminal recordings embedded in the READMEs. These results do not verify a remote VPS, cloud account,
production domain or full CRS conversion.

The same source commit passed Ubuntu/Windows × Node 22/24 in
[CI run 40188836636](https://github.com/jsw-teams/shieldweave/actions/runs/40188836636).
The local-process smoke harness subsequently switched from random consecutive port guesses to
OS-assigned port-zero listeners after reviewing an older Windows bind-conflict failure; that
startup/control/revocation smoke passed locally on Node 22.23.1 and 24.19.0.

## Backend/protocol extension, 2026-10-24

Windows Node 24.19.0 and 22.23.1: the initial **71 main tests passed**; **3 independent converter tests passed**.
`npm run check`
passed schema freshness, typecheck, lint, tests, build, five sandbox bundles, actual isolated tarball
installation/audit and local-process smoke. The final public-browser-origin policy adjustment was
also checked with typecheck and all 13 backend/protocol tests. Wrangler `cloudflare:dry-run` built
the real validation Worker (about 610 KiB / 132 KiB gzip). Full `npm audit` includes development
tooling and reports zero vulnerabilities. This is local validation; live account deployment and
production application adoption have not been performed.

New regression evidence: origin rotation/bypass, authentication versus ownership versus CSRF,
approved public browser origins independent of private backend host, strict JSON/byte limits,
secure cookies, private response headers/events, stuck-callback concurrency containment; progressing
media longer than its header deadline, idle/size/MIME/range rejection; fragmented gRPC-Web envelopes,
flags/lengths/status trailers, binary rule incompatibility; ordered two-way WS inspection, rate/size/
queue/idle/inspection deadlines and handshake IR/origin gates.

`tests/workerd.test.ts` starts actual isolated workerd Workers with service bindings and disposes
them in `finally`. It exercises 200/401, rule→L1→second-Worker L2, admin revocation with the documented
one-second polling bound, direct-origin rejection, media bytes and a **real 101 WebSocket upgrade
and bidirectional text/binary echo**. Its control Worker is explicitly a memory-only test fixture; durable
production authority is not claimed. The emulator ingress normalizes its internally injected Host;
separate raw/boundary tests still reject forged Host values. No network probe is sent to production.

The previous suite and benchmark below predate these protocol extensions; the benchmark has not
been rerun and must not be cited as their measured performance.

A later service-scope regression raises the suite to 72 tests: services sharing a tenant and a
complete policy cannot consume each other's cached blocks. Runtime, proxy and workerd regressions
passed after adding service/protocol-mode cache namespaces and capturing origin credentials.
The first GitHub run passed both Ubuntu jobs; Windows checkout line conversion exposed a schema
freshness failure. `.gitattributes` now fixes source files to LF across platforms; no freshness
check was removed or relaxed. Final CI status is available in the repository's Actions history.

Local environment: Windows x64. All 56 main tests passed on Node.js 24.19.0 and 22.23.1. Node 22
emits an experimental SQLite API warning; Node 24 is recommended. CI includes Windows/Linux and
both Node lines, but no remote CI run or Linux execution is claimed. Generated local output lives
in ignored `artifacts/`; a measured benchmark snapshot is also committed below.

## Executed results, 2026-10-24

| Command / check | Result |
| --- | --- |
| `npm run check` | Passed: static schema, typecheck, lint, main tests, converter tests, build, edge checks, installed tarball verification and local-process smoke |
| `npm test` after the final HTTP integration test | 56 passed, 0 failed/skipped |
| Node 22.23.1 `--import tsx --test --test-reporter=spec tests/*.test.ts` | 56 passed, 0 failed/skipped |
| `npm run test:converter` | 3 passed, 0 failed/skipped |
| `npm run typecheck`, `npm run lint`, `npm run build` | Passed |
| `npm run check:edge` | All 5 provider browser bundles passed AST + no-codegen sandbox denial/proxy checks; unminified size about 576 KB |
| `npm run verify:package` | Built imports passed; actual tarball installed in an isolated temporary consumer; ESM exports and consumer production audit passed without inherited overrides |
| `npm run smoke:local` | Separate process: legal 200, rule→L1→revoke→rule, direct-origin 403, unauthenticated control 401 |
| Loopback HTTP authority integration | Two runtime instances used real fetch/TCP, runtime-role writes, L1/L2 and administrator revocation; no blocked request reached origin |
| CLI validate/explain/simulate/compatibility/assess/learn | Executed successfully; all 3 simulation samples passed; real Go fixture correctly evaluated golang.org/x/net 0.16.0 as affected; model file generated |
| `npm audit --omit=dev --audit-level=moderate` | 0 vulnerabilities |

Some final package/API-export and community checks were also executed independently after the
combined check; results above refer to the final files. No live cloud deployment is part of them.

## Measured local benchmark

`npm run benchmark`: 3,000 sequential requests per scenario, Node 24.19.0, Windows x64,
Intel i5-13500H, in-process memory store and offline origin. Snapshot:
[benchmark-win32-node24.json](benchmark-win32-node24.json).

| Scenario | P50 ms | P95 ms | P99 ms | CPU µs/request |
| --- | ---: | ---: | ---: | ---: |
| Legal allow | 0.155 | 0.380 | 0.578 | 198.0 |
| New rule decision | 0.121 | 0.393 | 0.720 | 182.3 |
| L1 repeat | 0.094 | 0.232 | 0.346 | 135.3 |
| Forced L2 hit | 0.102 | 0.275 | 0.400 | 161.3 |

L1 repeated-scenario hit rate: 99.967% including its first miss; forced L2 rate 100%. Attack origin
reach rate was 0 in these synthetic scenarios, synthetic legal-block rate 0. End RSS about 116 MB;
authority memory-store revoke operation about 0.45ms. These are local measurements, not cloud or
production performance/effectiveness guarantees.

Implemented checks cover:

- Legal proxying, origin credential replacement, forged forwarding-header removal, route/method/
  identity checks, tenant mismatch and no origin reach for blocked requests.
- Canonical paths, double encoding, bad hosts/framing, strict JSON duplicate keys and depth,
  body limits/deadlines, compression/multipart refusal, SSRF origin configuration restrictions.
- Actual loopback raw HTTP TE/CL rejection by the Node parser before the handler. This is not an
  H2/H3 cloud or historical vulnerable-server reproduction.
- YAML/Schema safety, boolean matching, numeric ranges, duplicate query values, transforms,
  conflict/regex limits, immutable policy hashes, scoring/rate/candidate semantics.
- First rule hit → L1 → another instance L2; TTL; revocation generation and stale writes; bounded
  state; tenant isolation; SQLite restart; HTTP client/API role gates; policy activation/rollback.
- Native compilation refusals; four API/SDK request contracts; Vercel draft activation/refusal;
  approval/hash tampering; unowned rules; capacity; drift; retry after ambiguous write; revoke.
- Real Go OSV interval boundaries, alias dedup, supported inventories, incomplete-data refusal,
  evidence/authorization gates and isolation false positives.
- Learning source quotas/independence, candidate separation, balanced training, freeze/rollback,
  API changes, shadow/canary gates and confirmed false-positive rollback.
- Community default no upload, independent consent, strict privacy fields, signatures, organization
  quorum, warnings, expiry, anti-replay and revocation; converter refuses semantics it cannot retain.
- Browser-target bundles for five providers, AST inspection and a VM with string/wasm code
  generation disabled executing real regex denial and proxy paths. An early text-pattern checker
  falsely matched a RE2JS method named `eval`; it was replaced by AST inspection plus execution.
  AJV's online compiler was separately eliminated by the static validator generator.

No live cloud calls, public scans, historical vulnerable runtime crashes, real customer datasets or
community reports were performed. Network research downloaded one public official Go advisory;
all malicious request regression traffic stays in process or on loopback.

Benchmark interpretation: `npm run benchmark` measures local sequential in-process runtime behavior
with an offline origin, no cross-region storage/network or cloud cold starts. Report P50/P95/P99,
CPU µs/request, heap deltas and process memory, cache hits/evaluation counts. Heap deltas include
GC effects; they are not retained per-request allocation. Authority transaction time is not global
revoke propagation latency. Production false-positive rate and cloud native enforcement time are
unavailable and must not be inferred from unit fixtures.

中文：验证结果只对实际执行的环境和支持配置负责。Mock 用于接口契约，沙箱用于可移植性，
真实云防火墙效果与生产误报率仍需要单独记录。请勿把这些不同层级的证据混为一谈。

## Actual VM and CalVer release, 2026-10-25

The existing CodexRecordingVM WSL2 guest uses kernel 6.18.33.1-microsoft-standard-WSL2 and Node 22.22.0. The recorder installs actual built tarballs, executes 29 real commands in xterm and records the X11 desktop using FFmpeg. It verifies native IR import, source pins, TLS origin authentication, HTTP 200/403, rule/L1/L2, a second runtime process, revocation, independent SecLang conversion, activation/rollback, checksum refusal and lossy refusal. Source cloud/VPS example inventory is distinct from the isolated HTTPS test origin. No real provider account or external VPS is probed.

2026.10.2 removes manual source checksum settings. Digests are computed internally; conversion
reports must match actual bytes. Changed native IR is a new candidate with new provenance, not an
automatically trusted update. Windows npm run check passes 78 main tests and 3 converter tests,
including report/source tampering and rejection of the removed configuration field.

Real VM installation exposed and fixed CLI public-Host/listener coupling and the Linux npm-bin symlink entry guard. The new TCP child-process regression and installed-package verification cover these issues. CalVer YYYY.M.N is checked against the CLI version constant.

Final local check on Windows Node 24.19.0: npm run check passes 77 main tests and 3 converter tests, schema/version/typecheck/lint, five edge sandboxes, build, installed-tarball imports/CLI execution/audit and process smoke. The recording uses the independently installed Linux CLI binary (including its real npm symlink). The native IR source is fetched over an actual isolated HTTPS connection before checksum and Schema validation. No response is stubbed by a browser controller.

## Weekly maintenance, 2026-10-26

The real registry repair planner selected Biome 2.6.3 and the Tencent SDK 4.1.332 within existing compatible ranges, with zero remaining audit findings. The full npm run check suite passed 89 main tests and 3 converter tests, including two maintenance regressions. Temporary resolution locks are removed outside the checkout. Remote scheduled publishing verification is recorded in GitHub Actions; these local results do not claim that every platform permits bot pushes.
