# Weekly dependency repair / 每周依赖检查与自动修复

Dependency checks run weekly, separately from hourly rule-source synchronization. Dependabot checks
on Monday at 03:00 Asia/Taipei; scheduled audits run at 03:17 and automatic repairs at 03:37.
The converter has its own 03:47 repair job. Scheduled GitHub jobs may start late under runner load.
Normal source pushes still run existing affected checks.

The shared [maintenance workflow](../.github/workflows/dependency-maintenance.yml) is reused by
EdgePress, the document/media viewers and the operator API deployment. Its configurable directory
restricts changes to one package manifest. The private web caller selects only `api.js.gripe`.

1. Resolve current compatible versions in a disposable directory, with lifecycle scripts disabled.
2. Increase simple `^` / `~` minimum versions within their approved ranges. URLs, Git references,
   prereleases and custom ranges keep their declared intent.
3. Audit the fresh tree. If an exact transitive dependency remains vulnerable, select an available
   non-vulnerable version compatible with every installed major/minor line and record an override.
   No downgrade or forced major upgrade is allowed; pre-1.0 compatibility follows caret semantics.
4. Audit again. Archive the proposed manifest and report before running new dependency code.
5. Install the proposed tree and run the caller's complete relevant regression/build commands in
   a job with read-only repository access and no deployment credentials.
6. A separate publishing job, which does not execute dependencies, accepts only manifest dependency
   fields. Verified repairs use a normal, non-force push from the exact tested base revision.
   Branch protection, concurrent changes, unresolved advisories or failed tests retain a repair PR
   for review instead of bypassing the protection. If no compatible repair is available, the run
   fails visibly with its report; it never reports the finding as fixed.

The publishing job uses the built-in scoped GitHub token. No new long-lived Secret or runtime
variable is required. Library npm/GitHub releases still follow their existing release process;
this workflow repairs source manifests and does not automatically publish packages. The operator's
existing GitHub-connected application build may deploy a verified API manifest commit normally.

Repositories retain no lockfiles. Audit/repair operations temporarily create resolution snapshots
outside the checkout and delete them afterwards. This deliberately gives up a retained reproducible
dependency tree, following the operator's explicit policy; current resolution and test results are
recorded by each workflow. Upstream registry advisories and finite regressions cannot prove the
absence of supply-chain attacks or all behavioral regressions.

Local validation: two isolated mocked-npm tests verify same-major security repair, refusal of a
breaking upgrade, disabled lifecycle scripts and absence of retained locks. An actual registry
resolution updated two compatible dependencies with zero remaining findings; the full project
suite then passed. See [validation evidence](VALIDATION.md).

中文：每周自动处理兼容范围内的问题，测试、审计通过后才自动提交；不跨主版本强修、
不关闭分支保护、不写入应用代码或运行时配置。失败保留真实错误与修复候选，不能把生成 PR
当作问题已经修复。常规 npm 发布仍遵守项目原有发布流程。
