# Configuration-driven protection sources / 配置化防护来源

Two distinct inventories share a versioned [JSON Schema](../integrations/rule-converter/sources.schema.json).
An operator-owned YAML/JSON file defines both. Request parameters never select an upstream or rule URL.
This is a control-plane import facility; it runs outside the online request path.

两类来源均通过配置文件设置，完整实例见 [sources.yaml](../examples/sources/sources.yaml)：

- `upstreams`：云服务或第三方 VPS 的固定 HTTPS 源站，`kind` 仅用于资产分类，不改变检测能力。
  配置独立 `originTokenEnv`、代理超时和最大响应量。拒绝 HTTP、URL 凭据、路径、查询参数。
- `ruleSources`：明确启用、来源版本、许可证、格式、业务作用域。配置不含 `sha256` 设置。
  本地文件必须位于配置目录中；远端只接受配置中精确的 HTTPS URL。
  `permittedLicenses` 是部署者明确允许的许可证列表，并不代替法律评估。

## Protect a cloud origin or third-party VPS

```sh
npm install
npm run build
node dist/packages/cli/main.js sources-check examples/sources/sources.yaml
# Edit the example HTTPS origin, publicHosts, routes and secret environment references first.
node dist/packages/cli/main.js serve examples/shield-vps.yaml
```

`upstream.file` 相对运行配置解析，`upstream.id` 选择固定源站，不能同时声明另一组内联源站。
`SHIELD_VPS_ORIGIN_TOKEN` 与 `SHIELD_CLIENT_TOKEN` 必须是不同的至少 32 字符随机密钥。
源站必须验证注入的 `x-shield-origin-auth`，限制网络入口，禁止直接绕过；服务端默认 TLS
验证不得关闭。示例没有自动修改 VPS 防火墙或云平台配置，也不自动签发证书。
CLI 默认示例监听回环地址；容器可显式监听 0.0.0.0；前置 TLS 入口的 Host 必须与配置一致。客户端分组使用实际 socket
对端，不能把任意 X-Forwarded-For 当作可信身份。应用级 OAuth/对象授权应由真实认证回调接入。

The same portable engine can protect an HTTPS origin on any hosting provider. Runtime portability
does not imply native WAF management support: see [platform coverage](../CLOUD-ADAPTERS.md).
Deploying the Node listener behind a verified TLS ingress is supported locally; production HA,
certificate provisioning, network isolation and platform-specific protocols remain operator tasks.

## Import a rule source

```sh
# Offline, native YAML IR; output must be a NEW file.
node dist/packages/cli/main.js sources-import examples/sources/sources.yaml local-ir candidate.json
node dist/packages/cli/main.js validate candidate.json
node dist/packages/cli/main.js explain candidate.json
# Test with your own normal/attack corpus, then explicitly set policyFile and reload the runtime.
```

远端下载没有默认定时开启，只在执行导入时访问明确配置的来源。下载不携带业务数据；可通过 authTokenEnv 向指定 HTTPS 来源发送独立只读凭据，
禁止重定向与压缩，限制 5 秒和 128 KiB，解析前自动计算来源摘要并记录到候选规则 provenance。访问私有 HTTPS 规则服务器可用，
但规则配置必须由可信管理员维护；不是面向不可信租户的任意 URL 下载服务。文件路径包含
符号链接时，其目标也必须由该管理员控制。现阶段每次导入一个固定来源，没有自动合并冲突。

For a non-IR source, run the **separate** converter on the exact source bytes:

```sh
node api-shield-convert/src/cli.mjs examples/sources/method.conf seclang method.conf demo-1 Apache-2.0 api > report.json
node dist/packages/cli/main.js sources-import examples/sources/sources.yaml seclang-method candidate-method.json report.json
```

`exact`/`runtime-only` 且无语义限制的转换结果才可导入；`partial`、`unsupported`、来源不一致、
哈希错误、未批准许可证或跨业务作用域均拒绝。完整 CRS、Sigma、Nuclei、Suricata 不会被当作
等价单条 block 规则。没有内置或默认下载第三方规则集。导入产生**候选文件**，不会自动部署
或变更活跃策略；AI 输出和转换器自报 exact 都不能替代攻击/正常样本回归。

The source inventory has no manual checksum option. The importer computes SHA-256 internally for
audit provenance and verifies a converter report against the actual original bytes. This is not an
independently approved integrity pin: a remote URL may change its content while declaring the same
version. Review candidate diffs and regressions before explicit activation; unattended activation
from mutable remote sources is not supported. 项目不保存依赖锁文件；每日重新解析、审计并通过回归验证更新。

公共及私有库支持[定时同步](RULE-SYNC.md)，凭据只通过环境变量注入。签名 feed 信任链和镜像回退仍未实现。
No cloud-management API is called by these commands.

The Node CLI accepts one exact public Host independently of its loopback listener address; requests through a TLS ingress must preserve that configured Host. Port 0 explicitly requests an OS-assigned local listener. These settings are exercised in the actual VM terminal recording and TCP regression.
