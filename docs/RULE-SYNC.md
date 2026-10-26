# Scheduled rule synchronization / 公共与私有库定时同步

This background pipeline fetches configured source bytes, validates license/scope/IR or converter
provenance, runs the real runtime against local attack/legitimate samples, and archives candidates
in SQLite. Sources are candidates by default. Explicit automatic-application configuration enables
validated rebuilds of the active policy. Network downloads run outside the request path.

## Automatic application / 自动应用

```yaml
application:
  policyFile: rules/active.json
  baselineFile: rules/baseline.json
  regressionFile: rules/regression.json
  service: api
```

Set `autoApply: true` and `regressionFile` on each authorized source. Run
`shieldweave sources-apply sources.yaml`, or enable `sources-sync` / `sources-watch` with this
configuration. Every enabled rule must independently match an attack sample; both attack and
legitimate samples are required per source and in the merged policy. The baseline is always
retained. Duplicate IDs, incompatible semantics, conversion loss and failed regressions reject
the entire update. A file lease excludes concurrent writers; an fsynced temporary file is atomically
renamed over the active file. Identical updates do not rewrite it. Disabling/removing a source
withdraws its rules after the next successful rebuild. A failed update preserves the last active file.

The currently approved automatic profile is stateless request-header block rules over path,
method, header and query. Other rules remain reviewable candidates. Node `serve` reloads a valid
changed policy within one second on the next request and keeps its existing engine on invalid
updates. A policy version change starts fresh L1 state and uses versioned L2 keys. Edge deployments
can commit the tested policy to their Git-connected deployment repository and rebuild the Worker.
`createHeaderPolicy` executes the same matcher before native handlers without consuming DNS/WS
bodies; it does not replace their authentication. Native L0 firewall publishing remains separately
authorized through the cloud adapters.

For a private deployment repository, run synchronization in that repository's scheduled workflow.
Checked-out private files can be configured as relative sources; no cross-repository token or
Worker variable is needed. For a separate private repository, use the Contents API and a scoped
Contents:read credential. Keep generated private policy artifacts inside the private deployment
repository. Git provides revision history and rollback of the applied bundle.

```yaml
version: "1"
upstreams: []
permittedLicenses: [Apache-2.0]
ruleSources:
  - id: organization-rules
    enabled: true
    location: https://api.github.com/repos/YOUR-ORG/YOUR-PRIVATE-REPO/contents/policy.yaml?ref=main
    authTokenEnv: RULE_REPOSITORY_TOKEN
    format: shield-ir
    version: main
    license: Apache-2.0
    service: api
    regressionFile: regression.json
```

The same HTTPS configuration works for a public source: omit `authTokenEnv`. No manual SHA-256
setting is required. The importer computes a digest from actual bytes and records it as provenance.
An immutable commit in `ref` is preferable for reviewed imports; a moving branch enables update
discovery. The configured license is an administrator assertion, not an automatic license detector.

For a private GitHub repository, create a fine-grained token restricted to that repository with
Contents:read; place it in the named environment variable or deployment Secret. Do not put the
token in URLs, YAML, Git or logs. The GitHub Contents endpoint returns raw file content using
`Accept: application/vnd.github.raw+json`. Redirects are rejected so a token cannot follow one to
another host. A source has a 5-second deadline and a 128 KiB maximum, with compression rejected.
Larger rule sets must be divided into independently configured sources; whole CRS archives are
not a supported import format.

`regression.json` is operator-controlled, relative to the source configuration directory:

```json
[
  {"name":"attack case","kind":"attack","url":"https://simulation.test/api?q=attack","expectedStatus":403},
  {"name":"normal case","kind":"legitimate","url":"https://simulation.test/api?q=hello","expectedStatus":204}
]
```

These examples assume a corresponding reviewed query rule; they are not a complete attack corpus.
Each sample gets an independent runtime/cache, preventing an earlier cached block from masking a
nonmatching attack. Both classes are required. The origin is in-process and returns 204, so sample
execution cannot send traffic to a production target. Verification here is a finite regression result,
not proof of complete protection or absence of false positives. Stateful rate-window test sequences
are not implemented in this source-regression profile; use dedicated runtime tests for those rules.

```sh
# One scheduled batch; unchanged sources are due again after an hour.
shieldweave sources-sync /etc/shield/sources.yaml /var/lib/shield/candidates.db
# Export a verified candidate for review, without activating it.
shieldweave sources-export /var/lib/shield/candidates.db organization-rules HASH review-policy.json
# Serial polling daemon, no overlapping fetch batches; 60..86400 seconds supported.
shieldweave sources-watch /etc/shield/sources.yaml /var/lib/shield/candidates.db 3600
```

For Linux install `deploy/standalone/shield-source-sync.service` and `.timer`, set the independent
read-only credentials in `/etc/shield/rule-secrets.env` (0600), then enable the timer explicitly:

```sh
sudo cp deploy/standalone/shield-source-sync.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now shield-source-sync.timer
```

For a local/VPS/cloud container scheduler, run the one-shot CLI on your chosen schedule. The job
does not require a GitHub Actions runner or a cloud-specific API. Use a separate database per
tenant and source inventory, and restrict filesystem access: archives contain private source bytes.
Default capacity is 1000 source revisions and 10000 audit records; capacity exhaustion fails closed
until the operator archives/migrates records. It does not silently discard audit evidence.

Candidate states: `needs-conversion` preserves non-IR bytes; `needs-regression` is validated IR;
`verified` has passed configured samples. Third-party sources use `conversionReportFile` from the
independent converter. Changed bytes that no longer match the report fail import. Partial or
unsupported conversions cannot become verified policies. Download/import/test failure leaves
previous archived candidates intact, records a redacted failed attempt, and makes the one-shot
CLI exit nonzero. Without `application` and source `autoApply`, imports remain candidates.

中文：定时任务只有部署者显式启动后才运行。支持公共、私有 HTTPS 规则库，凭据独立且只读；
不上传业务流量。显式授权的规则源在独立样本与合并策略回归通过后自动应用；更新失败保留上一版。

References: [GitHub Contents API and raw media type](https://docs.github.com/en/rest/repos/contents), [Docker Compose security/resource fields](https://docs.docker.com/reference/compose-file/services/).
