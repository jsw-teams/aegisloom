# EdgeShield · 边缘盾

自研 TypeScript SecLang 编译器和执行引擎，直接运行完整 OWASP CRS，不转换为 Shield IR。Cloudflare、Vercel、Netlify、ESA、EdgeOne 和 Node/VPS 共用同一套规则执行代码。Cloudflare 部署只需要 Worker。

## 目录

- `scr/`：引擎、HTTP 运行时、平台适配器、CLI、回源协议。
- `tools/`：维护工具和测试；依赖、构建、缓存、运行状态分别位于其下的 `node_modules/`、`.build/`、`.cache/`、`.state/`。
- `rules/`：完整上游源码包、同步配置、白名单和用户规则。
- `secret/`：项目凭据和回源密钥；实际文件不进入 Git 或 npm。
- `origin/{cloudflare,vercel,netlify,esa,edgeone}/<业务>/`：各平台自己的回源配置和可选业务函数。
- `respond/`：用户自定义拦截 HTML、JSON。

普通设置在根目录 `config.yml`，GitHub Actions 使用标准 `.github/` 目录。本文是唯一说明文档；许可证单独保留。

## SecLang 引擎

当前锁定 OWASP CRS v4.30.0，提交 `e03a4f6dabc7a30ebd8c52c97d28a154f590a48f`。原始 setup、所有规则及引用的数据文件一起加载：693 条 SecRule、8 条 SecAction，共 701 个执行步骤、628 条根规则。编译器核对每条源规则；缺失文件、重复 ID 和不支持的语义使严格加载失败，不完整的程序不能执行。

实现 CRS 使用的变量集合、计数、选择和排除、PCRE2、转换链、multiMatch、宏、TX、capture、chain、phase 1–5、SecDefaultAction、setvar、initcol、skip/skipAfter、ctl、异常评分及匹配日志。请求中断后仍执行 phase 5。实际解析 URL 编码、JSON、XML/XPath、multipart 和二进制请求；响应阶段检查源站返回的头与正文。

PCRE2 和 libinjection 仅作为匹配原语库，通过自研 WASM 适配层调用，来源、哈希及许可证在 `scr/seclang/vendor/`。规则解析、事务、状态与决策由 EdgeShield 实现，不依赖第三方 WAF 引擎，没有正则翻译、RE2 回退或按平台裁剪规则。

兼容范围以锁定的完整 CRS 和执行回归为依据。Apache 服务器配置、外部脚本等不属于已验证的规则指令范围。

## 安装和运行

```sh
npm install
npm run serve
```

安装会把依赖放到 `tools/node_modules/`、编译到 `tools/.build/`，并仅在密钥文件不存在时创建随机凭据。已有密钥不会被覆盖。

npm 包提供独立 CLI：

```sh
npx @jsw-teams/edgeshield init .
npx @jsw-teams/edgeshield serve config.yml
```

修改 config.yml 的 platform、域名、路由和监听地址。Node/VPS 读取选定平台的 `origin/<平台>/<业务>/config.yml`；没有单独的 Node 业务目录。默认监听回环地址，公网由自己的 TLS 入口承接。容器需要挂载自己的 secret，并按容器网络配置监听地址。

凭据均来自项目文件，不使用 Secret 环境绑定。云端私有构建会打包所需凭据，产物不能作为公开静态资源或 npm 包发布。Node 支持规则、白名单和自定义回应热更新；业务代码或监听地址修改后重启。

## 回源

每条路由必须通过 `business` 选择业务名。例如同一 EdgeOne 部署可以使用 `origin/edgeone/shop/index.js` 处理商城函数，`origin/edgeone/orders/config.yml` 回源订单 VPS，`origin/edgeone/search/config.yml` 回源搜索服务的负载均衡 CNAME。各业务配置独立，不能通过请求参数更换源站；同一引擎检查所有业务的请求和响应。构建只包含当前平台被路由引用的业务。

```yaml
routes:
  - path: /shop
    business: shop
    methods: [GET]
    authenticated: false
  - path: /orders
    business: orders
    methods: [GET, POST]
    authenticated: false
    body: text
  - path: /search
    business: search
    methods: [GET]
    authenticated: false
```

在各自的 `origin/<平台>/<业务>/config.yml` 选择模式。普通代理支持 VPS IPv4/IPv6、域名和负载均衡 CNAME：

```yaml
platform: cloudflare
mode: proxy
url: https://lb.business.example
```

也可填写 `https://192.0.2.10` 或 `https://[2001:db8::1]:8443`。使用正常 HTTPS 证书校验，不关闭验证。配置固定源站，拒绝跟随重定向；清理转发头，加入来自 secret 的 `x-shield-origin-auth`。外部业务应验证该令牌，避免绕过防火墙直连源站。请求和源站响应均经过同一个 SecLang 引擎。

平台内业务函数使用 `mode: function`，由 `origin/<平台>/<业务>/index.js` 默认导出的 `fetch(request)` 处理。默认业务只有健康检查，其他路径返回 404。构建器拒绝跨平台引用其他业务文件；代理模式不会加载这些函数。

加密中继可部署在 VPS 或支持 WebCrypto 的云函数：

```sh
npm run relay:init
node tools/.build/scr/cli/main.js serve-relay secret/relay-server.yml
```

密钥在 `secret/relay/`，服务器配置由 `secret/relay-server.example.yml` 初始化。云端只读取公钥和认证密钥，服务器私钥留在回源端：

```yaml
platform: cloudflare
mode: relay
endpoint: https://relay.example/_edgeshield/relay
publicKeyFile: ../../../secret/relay/public.jwk
authenticationKeyFile: ../../../secret/relay/authentication.key
```

协议使用 ECDH、HKDF、双向 AES-GCM、HMAC、请求绑定和时间窗口，VPS 用 SQLite 持久化防重放。保留二进制正文和多个 Set-Cookie，并限制实际字节数和读取时间。Node 中继默认监听回环地址，需放在 HTTPS 入口后；云函数可通过 `/relay` 的 `createRelayServer` 接入自己的原子性持久化 ReplayStore。

## 五个平台构建

```sh
npm run platform:build -- cloudflare
npm run platform:build -- vercel
npm run platform:build -- netlify
npm run platform:build -- esa
npm run platform:build -- edgeone
npm run cloudflare:dry-run
```

私有产物在 `tools/.cache/platforms/<平台>/`。Cloudflare 使用静态 WASM；其他入口加载相同 WASM 字节。Vercel 使用 Node Functions，Netlify 使用 Fetch 函数，ESA 使用 Fetch 入口，EdgeOne 使用 onRequest 入口。平台自己的载荷、CPU 和内存限制仍然适用。

CRS 的 REQUEST_PROTOCOL、REQUEST_LINE 和 REMOTE_ADDR 需要真实传输信息。Cloudflare 读取平台信息，Node 读取连接元数据。其他 Fetch 入口要求由可信入口用 `secret/credentials.yml` 的 ingressKey 签名传递原始协议/IP；缺失或伪造返回 503，不会编造 HTTP/1.1 或跳过相关规则。

`@jsw-teams/edgeshield/ingress` 的 `createIngressForwarder(destination, ingressKey)` 可接入现有可信 Node/Worker 入口，调用时传入实际 httpProtocol、verifiedClientIp，以及可用的 rawTarget。签名绑定方法、目标、原始 URL、元数据和时间戳；后端恢复请求再执行完整 CRS。客户端自报的转发头不能作为可信元数据。

## 本地防火墙指令

`rules/local.conf` 完全由用户控制，通过 config.yml 的 localRulesFile 加载，上游同步不会改写。可直接使用 SecLang 的 IP/GLOBAL 集合和 expirevar、deprecatevar 表达计数、滑动衰减及临时拒绝。例如：

```apache
SecAction "id:10001,phase:1,pass,nolog,initcol:ip=%{REMOTE_ADDR}"
SecRule IP:blocked "@eq 1" "id:10002,phase:1,deny,status:429"
SecRule RESPONSE_STATUS "@eq 403" "id:10003,phase:5,pass,nolog,chain"
    SecRule TX:blocking_inbound_anomaly_score "@ge 5" "setvar:ip.hits=+1,expirevar:ip.hits=60"
SecRule &IP:blocked "@eq 0" "id:10004,phase:5,pass,nolog,chain"
    SecRule IP:hits "@ge 3" "setvar:ip.blocked=1,expirevar:ip.blocked=300"
```

以上示例按实际 CRS 403 和分数累计；expirevar 在再次执行时重设期限，deprecatevar 按完整时间间隔递减且不低于零。集合有容量和过期边界，不能无限增长。默认 local.conf 不激活额外封禁。

纯 Worker 的集合属于当前引擎实例，不能提供跨实例、跨区域或重启后的全局计数。到期在访问时核验，不依赖实例存活到某个定时器；不会在平台上遗留需要额外清理的远程封禁规则。

## 白名单与拦截回应

`rules/allowlist.yml` 支持全局、规则 ID、路径/前缀、方法、身份、IP/CIDR 和可选过期时间：

```yaml
- id: trusted-search
  skip: [rules]
  ruleIds: ['942100']
  path: /api
  cidrs: [192.0.2.0/24]
```

省略 ruleIds 或填写 `['*']` 可豁免全部规则，也支持 sec- 前缀。默认没有豁免；白名单不绕过路由、认证、HTTP 边界或字节上限。

在 `respond/403.html` 放完整 HTML，例如 EdgePress 构建页面，403.json 定义 JSON 回应；其他 4xx/5xx 使用相应文件名。HTML 不插入请求内容，CSP 在 config.yml 中配置，保留拦截状态与 HEAD 语义。

## 上传与验证

配置读取的 8 MB 上限与 HTTP 上传无关。limits.maxBodyBytes 控制实际上传字节，项目默认 8 MiB，最高可配置 16 MiB，不相信 Content-Length。完整 CRS 下验证大于 2 MiB 的 multipart 文件保真回源，普通恶意字段仍被检查。

单个转换值上限 2 MiB；PCRE2 的步数、深度、内存以及状态集合有资源边界。超限中止并拒绝，不能当作不匹配放行。压缩请求正文及原始 gRPC 帧未提供入口。显式 websocket 路由检查真实握手及 101 响应头，保持平台原生二进制消息；升级后的不透明消息不交给 SecLang 检查。

```sh
npm run test:crs
node tools/sync-native-seclang.mjs --latest
# npm CLI 也提供相同的严格同步器
edgeshield sync --registry rules/seclang-upstreams.json --output rules/seclang-bundle.json
npm run check
npm run cloudflare:dry-run
npm run audit
```

rules/seclang-upstreams.json 支持多个来源。同步核对不可变 Git blob 和 SHA-256，严格加载全部源码，核对每条规则的执行指令，再运行正常/攻击/响应及性能回归，全部通过后原子替换源码包。GitHub Actions 每周验证并更新 main，用户规则、白名单和凭据不参与同步。

CI 覆盖 Linux/Windows、Node 22/24；包括完整 CRS PL1–4、五平台构建入口、真实 workerd、capture/chain/TX/ctl、误杀、SQLi/XSS/LFI/RCE、官方 WebShell 响应签名、上传、回源、防重放、TTL 指令、npm 独立安装和性能。没有用忽略规则或模拟匹配代替执行。本地验证不等于已在五家云账户部署。
