# Local servers, VPS and containers / 独立部署

AegisLoom is a normal Node.js service, independent of cloud functions. The same rule engine,
origin authentication, bounded streams and decision cache run on Windows, Linux and macOS.
Cloud-provider adapters add deployment bindings and optional native WAF management.

## Node process

Install Node 24, then in the repository run `npm install && npm run build`.
Copy `examples/shield.yaml` to your configuration directory and set its policy path, exact public
Host, routes, fixed HTTPS origin and SQLite path. Define `SHIELD_ORIGIN_TOKEN` as an independent
random credential of at least 32 characters. The origin must verify `x-shield-origin-auth` before
business routing and restrict its network ingress to Shield.

```sh
node dist/packages/cli/main.js serve /etc/shield/shield.yaml
```

For a same-host origin, explicit `allowLoopbackHttp: true` permits HTTP only to the literal
127.0.0.1 or ::1 address. It never permits unencrypted HTTP to a VPS hostname or container alias.
HTTPS certificate verification is always enabled. This option is for a trusted same-host boundary.

## Docker Compose

Edit this directory's `shield.yaml` with your real hostname/origin and routes; put reviewed policies
in `rules.yaml`. Export the origin credential in your shell, then:

```sh
docker compose -f deploy/standalone/compose.yaml up --build -d
docker compose -f deploy/standalone/compose.yaml logs --tail=100 shield
docker compose -f deploy/standalone/compose.yaml down
```

The image runs as UID 1000 without added capabilities. Compose uses a read-only root filesystem,
a persistent `/data` volume, bounded memory/processes and a host-loopback port. Never publish
8787 directly to the Internet. Place a TLS ingress on that host; the provided Caddyfile preserves
the configured public Host and removes user-supplied forwarding headers. Obtain certificates
and configure DNS/firewall rules through your own authorized deployment process.

## Linux systemd

Create an unprivileged `shield` system user. Install the built package and production dependencies
under `/opt/shield`; install your policy/configuration under `/etc/shield`. Use a loopback listener
and set `decisions.path: /var/lib/shield/decisions.db`. Store the origin credential in
`/etc/shield/secrets.env` (root-owned mode 0600), then install the provided `shield.service`:

```sh
sudo cp deploy/standalone/shield.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now shield
sudo journalctl -u shield --since today
```

Commands are operator instructions; this project does not install host services automatically.
The service assumes `/usr/bin/node`; adjust this path for your distribution.

## Verification and limits

`npm run test:integration` includes a real standalone CLI child process, authenticated HTTP origin,
normal forwarding, rule→L1 blocking and SQLite→L2 recovery after a process restart. The test uses
explicit loopback HTTP and no external network. The container/Linux service profiles have not
been executed on this Windows host because no Docker engine is installed.

The Node entry point currently handles HTTP/1.1 and bounded streaming responses. Cloudflare's
experimental WebSocket transport is separate; Node WebSocket upgrades and native gRPC transport
are unsupported by this entry point. Do not infer those capabilities from HTTP proxy support.
It groups by the real TCP peer; behind Caddy all clients share that peer. It never trusts arbitrary
X-Forwarded-For. Per-client bans/rate windows require a separately verified identity integration.
SQLite is a single-host authority, not a multi-region database.

中文：本地、第三方 VPS、自建云及容器都能运行防护进程，不要求云函数。原生云 WAF 联动
是额外能力。先配置固定源站、身份验证、路由、TLS 入口与隔离，再上线；部署在哪里不会
自动解决源站绕过问题。定时规则同步见 [RULE-SYNC](../../docs/RULE-SYNC.md)。

References: [Caddy reverse_proxy headers](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy), [Node HTTP server](https://nodejs.org/api/http.html).
