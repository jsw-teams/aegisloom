# Contributing / 贡献

Use Node.js 24 and npm. Run `npm install`, `npm run check`, `npm run check:edge`, and
`npm run test:converter`. CI runs unit, integration, security, typecheck, lint, build, static-schema,
edge-bundle and package checks on Windows/Linux and Node 22/24. CI is configured, not claimed to
have executed remotely before the repository is published.

Keep Web APIs in the runtime graph. Add cloud management SDKs only under adapters/control code.
Do not bundle third-party rules. Do not import the independent converter into Shield Core. Changing
the IR schema requires `npm run schema:generate`; commit the generated validator and compatibility
tests. Generated code is excluded from lint and checked for reproducibility instead.

Security changes need regression evidence for attacks, legitimate traffic, missing trust metadata,
resource limits and revocation. External tests must use authorized isolated resources. Mock tests
must be named and distinguished from live tests. New cloud compilers must reject unproven semantic
equivalence and preserve all conditions/provenance. Credentials never belong in fixtures or logs.

For a cloud release record provider, plan, region, runtime version, protocol terminator, rule quotas,
test time, actual requests/readback and rollback result. Redact secrets and customer data. The
existing validation record has **no live provider results**.

中文：按功能提交小改动，保留跨平台能力；提交前运行完整检查。新增安全能力必须明确可观察
边界和失败策略，回归覆盖攻击与正常业务，不能只测示例字符串。独立转换器使用自己的包、锁
文件和测试，拆出独立仓库后不应依赖主仓库路径。贡献以 Apache-2.0 提交。

Releases use YYYY.M.N: year, month (without a leading zero), and this project’s release ordinal in that month. Never change an existing tag or replace a package asset. Use npm version YYYY.M.N --no-git-tag-version to synchronize the CLI constant, then run npm run check. The independent converter counts its releases independently.
