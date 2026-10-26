# Cloud API Shield

[配置云端/VPS 源站与规则来源](docs/SOURCE-CONFIG.md)

[English](README.md) · Apache-2.0 · TypeScript / ESM · Node.js 22.13+（推荐 24）

采用 **YYYY.M.N** 版本号：`2026.10.1` 为 2026 年 10 月第 1 次发布；同月递增最后一段，跨月重置。Git 标签加 `v`，已发布版本不修改。

## 虚拟机实际操作

以下 GIF 直接录制已有 CodexRecordingVM（WSL2）的真实 Openbox 桌面和 xterm。终端执行实际安装的 CLI，在隔离 HTTPS 源站上验证，使用单独信任的本地证书，没有定制 HTML 控制台或伪终端，没有生产数据或云 WAF 发布。SQL 形态载荷用于验证画面中自编规则，不能据此声称完整 SQL 注入或某个 CVE 防护。

云端/VPS 配置、固定来源导入与 Schema 校验：

![虚拟机终端实录：配置与规则来源导入](docs/media/vm-sources.gif)

正常转发、首次规则拦截、L1、第二进程 L2、源站身份验证和撤销：

![虚拟机终端实录：拦截、缓存和撤销](docs/media/vm-blocking.gif)

独立 SecLang 子集转换、显式启用与回退、转换后原文变更及有损转换拒绝：

![虚拟机终端实录：转换器与策略回退](docs/media/vm-converter.gif)

[完整虚拟机录像及机器断言证据](https://github.com/jsw-teams/api-shield/releases/tag/v2026.10.2)。完整 CRS、原生 gRPC 不支持；真实云账号验收仍未完成。

复录前使用已有的专用 WSL2 录制环境，具备 Xvfb/Openbox/xterm/xdotool/FFmpeg/Node；不会安装或启用 WSL：

```sh
npm install
npm run build
npm pack --pack-destination artifacts
# 在 api-shield-convert/ 执行 npm install 和 npm pack --pack-destination ../artifacts
npm run demo:record
```

录制器对 29 条真实终端命令进行断言，通过 FFmpeg x11grab 录制。结束后停止自己的验收进程；若由录制器启动 VM，则关闭该专用 VM，不要指向正在运行其他任务的虚拟机。

跨云 API 安全框架：严格请求边界、可读规则、带撤销语义的安全决策缓存、持久化控制面，
以及可解释的离线漏洞响应和主动学习组件。核心引擎使用标准 Web APIs，云 SDK 和 SQLite
位于独立模块，不进入边缘运行时依赖图。

**当前交付是有实际代码和测试的首个版本，不代表完成全部六个阶段，也未经生产认证。**
Phase 1 的安全闭环已实现。后续阶段的已实现组件和缺口逐项记录在
[开发状态](docs/STATUS.md)、[测试证据](docs/VALIDATION.md) 和 [威胁模型](docs/THREAT-MODEL.md)。
没有使用云账号、部署生产规则、执行外部漏洞扫描或上传 IP。

本地验证包括实际 TCP 控制面、独立进程启动、源站隔离及撤销回归、五家边缘沙箱，
以及 Cloudflare 本地 workerd 的真实 WebSocket 升级、媒体流和跨实例决策测试。
最新测试命令、数量和适用环境见 [验证记录](docs/VALIDATION.md)。
本项目独立于 Cloudflare 的商业 API Shield 产品。

## 已实现的范围

- `packages/rule-ir`：版本化 JSON Schema、YAML/JSON、AND/OR/NOT、字段/存在性/范围、
  RE2 正则、有序变换、优先级、确定性冲突检查、请求内评分、过期时间、解释及回归模拟。
  Schema 在构建期编译，边缘运行时无动态代码生成。复杂逻辑重叠的 SAT 级分析尚未实现。
- `packages/http-boundary`、`core`、`runtime`：路由与身份检查、路径规范化、严格正文读取、
  JSON 重复键拒绝、来源头清理、固定源站白名单、源站令牌、TLS、超时、熔断与有界流式响应。
  默认 HTTP 模式拒绝压缩正文、multipart 和协议升级；WebSocket 必须显式启用独立适配器。
  响应阶段规则和交互挑战尚不支持。
- [后端统一标准](BACKEND-STANDARD.md)：可复用源站验证/轮换、严格 JSON 中间件、必选身份与
  对象授权回调、会话写操作 CSRF、日志脱敏、响应及 Cookie 安全校验。`backend-check` 只验证
  配置，不代表既有业务已接入或现网已通过安全验收。
- [协议分型](PROTOCOLS.md)：媒体流支持单 Range、MIME 白名单、响应头/空闲分别超时、并发和
  传输量限制；WebSocket 支持同一 IR/缓存的握手检查及双向消息大小/频率/队列/会话限制；
  二进制 gRPC-Web 支持受限请求和流式响应包络检查。后两项为 experimental。
  原生 gRPC 需单独协议入口验证，目前适配器为 unsupported；不会冒称能够检查原始 HTTP/2 帧。
- `decision-cache`、`control-plane`：有界 LRU/TTL、请求指纹决策、L2 接口与共享进程参考实现、
  跨进程 HTTP 客户端、SQLite WAL 权威存储、租户代际号、CAS 写入、撤销、审计、
  管理员/运行时权限分离、策略版本保存和激活回滚。不是简单缓存 HTTP 403。
- 五个平台都有边缘入口包装器，并通过浏览器目标打包及禁止 eval 的沙箱检查。
  Cloudflare、Vercel、ESA、EdgeOne 具有真实管理 API/SDK 实现与离线发布/回读/撤销测试。
  L0 编译目前严格支持方法与规范 IPv4 等值的逻辑组合，其余条件保留 L1 检测。
  Netlify 未核实同等公开原生 WAF 管理 API，相关操作明确为 `unsupported`。
- `vulnerability`、`integrations/sbom`：真实 Go OSV 数据回归、OSV 查询、别名去重、
  受限生态的版本评估、CycloneDX/SPDX/npm lock 导入、CVE5/KEV/EPSS 数据导入和条件增量拉取，
  以及经过攻击/正常样本验证与预授权门控的临时功能隔离。
  不会从 CVE 标题编造精准虚拟补丁，也不自动认定服务器已经修复。
- `learning`：可信来源隔离、每来源配额、独立来源均衡训练、OpenAPI 发现、EWMA 与参数类型
  基线、可解释异常、候选规则、模型冻结与回滚、Shadow/Canary 门控。
  属于 experimental 离线/库能力，默认不自动收集业务数据、不自动训练或上线。
- 独立的 [api-shield-convert](api-shield-convert/README.md) 工程支持严格 SecLang 子集；
  CrowdSec 仅输出带语义限制的 partial 结果，不能自动上线。未内置第三方规则集。
- 可选社区模块有独立上传/订阅/执行开关、Ed25519 签名、组织独立性门槛、Warning List、
  TTL、防重放与撤销测试。公共服务、身份信誉运营、持久化签名序号和申诉平台尚未交付。
  默认三个开关全部关闭。

Cloudflare [独立验证入口](deploy/cloudflare/README.md) 已有 Worker 配置和 dry-run 命令；
默认禁用 workers.dev、预览和路由。当前没有变更生产域名、原业务 Worker、绑定或防火墙。

## 本地启动与验收

```sh
npm install
npm run check
npm run test:converter
npm run check:edge
npm run dev
```

只监听本机：Shield `127.0.0.1:8787`，需要源站令牌的 API `8788`，控制面 `8790`。
决策持久化到 `shield-local.db`。按 Ctrl+C 关闭。可提前设置 `SHIELD_ORIGIN_TOKEN`、
`SHIELD_ADMIN_TOKEN`、`SHIELD_RUNTIME_TOKEN`，每项至少 32 字符；未设置时，本地启动会
生成不打印的随机令牌。管理令牌和运行时令牌必须不同。

```sh
curl "http://127.0.0.1:8787/api/echo?q=hello"
curl "http://127.0.0.1:8787/api/echo?q=shield-attack-test"
curl "http://127.0.0.1:8787/api/echo?q=shield-attack-test"
curl "http://127.0.0.1:8788/api/echo"
```

依次应为 200、规则阻断 403、L1 命中 403、直接访问源站 403。示例攻击标记仅用于验证流程，
不是通用 SQL 注入或 RCE 检测器。多个运行时的 L2 查询、TTL、撤销及竞态由自动测试验证。

```sh
npm run build
node dist/packages/cli/main.js validate examples/rules.yaml
node dist/packages/cli/main.js simulate examples/rules.yaml examples/samples.json
node dist/packages/cli/main.js compatibility examples/rules.yaml
node dist/packages/cli/main.js assess examples/inventory.json tests/fixtures/GO-2023-2102.json
npm run benchmark
```

## 部署与安全限制

请先阅读 [部署说明](DEPLOYMENT.md)、[规则手册](RULES.md)、[平台能力](CLOUD-ADAPTERS.md)、
[CVE 自动化](CVE-AUTOMATION.md)、[社区情报](THREAT-INTELLIGENCE.md)、
[架构](ARCHITECTURE.md) 和 [安全说明](SECURITY.md)。

Web `Request` 无法看到平台已经解析掉的报文帧、重复头的原始布局或 H2/H3 流控制。
源站必须自行校验 Shield 令牌并配置私网/防火墙隔离，不能仅靠隐藏域名。
默认撤销轮询间隔为 1 秒，严格模式可设为 0。决策缓存不可用时丢弃缓存并重新执行全部本地
安全规则；可以显式配置 fail-closed。身份、协议检查和源站白名单始终不会降级。
撤销缓存不等于删除仍然命中的检测规则；误报需同时回滚/修正规则。

所有平台均**没有真实账号验证**。L0 配置回读不等于全球节点已经生效；发布接口只接受明确
目标和具体计划哈希的授权，不自动提升一次低可信命中为 IP 级封禁。
基准只报告本地内存场景的实际数据，不声称云平台零计费或生产误报率。

许可证选择 Apache-2.0，便于跨云集成并提供明确专利授权；依赖和外部规则各自遵守原许可证。

Trusted HTML 403/404 pages: pass `errorPages` to `createShield`; each page contains build-generated
`html` and `contentSecurityPolicy`. Explicit HTML clients receive the configured page; JSON clients
retain JSON errors, and the status/HEAD/no-store semantics and decision-cache enforcement remain.
`@cloud-api-shield/shield/responses` also exports the framework-neutral responder for static adapters.
Never interpolate incoming URLs, headers, identities or rule evidence into a page.

Dependencies use compatible ranges and no tracked lockfile. Run `npm install`, `npm run check` and
`npm run audit`. Daily Dependabot PRs advance dependency constraints; the audit resolves a fresh,
disposable tree outside the checkout and removes it afterwards. Updates are tested before merging;
normal installation therefore resolves current versions rather than reproducing an immutable tree.
