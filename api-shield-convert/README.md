# api-shield-convert

Independent npm project; no dependency on Shield Core source and no bundled third-party rules.
Separate versioning, packaging and release lifecycle. This directory can be extracted to its own
repository without changing imports. Apache-2.0.

独立转换器工程，拥有自己的包、测试与发布周期。没有内置 CRS 或第三方规则文件。

```sh
npm ci
npm test
node src/cli.mjs operator.conf seclang operator-authored:test 1 Apache-2.0 api
```

Implemented: strict scalar `REQUEST_METHOD @streq` SecLang with explicit phase:1,
t:none, deny/pass and pinned provenance. Chains, inherited transforms, PCRE, state, macros,
scripts and CRS scoring are refused. CrowdSec METHOD condition extraction is **partial**:
alert/scenario/remediation semantics are retained as a compatibility limitation, never silently
turned into a block. Sigma, Suricata and Nuclei return **unsupported**. Prefer native Coraza/
CrowdSec integrations for full rulesets; those integrations remain planned.

部分转换不会被主项目的 `importConversion` 自动接受。转换成功不代表防护等价，必须运行原生
引擎差异测试及应用正常流量回归；当前测试只证明支持子集的语义和拒绝行为。
