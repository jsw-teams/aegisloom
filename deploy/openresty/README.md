# Optional OpenResty reverse-proxy profile / 本地 VPS 反向代理

**Cloud functions do not use OpenResty.** EdgeShield already has a real Cloudflare Worker `fetch()` handler. An eligible Cloudflare zone may use provider-managed Keyless SSL; the Worker receives an already decrypted HTTP `Request` and sends authenticated HTTPS traffic to its origin.

For a self-hosted Linux VPS, this profile enables:

1. Client HTTPS -> OpenResty on the selected ingress port.
2. OpenResty -> EdgeShield Node security engine at `127.0.0.1:8787`.
3. EdgeShield -> authenticated OpenResty bridge at `127.0.0.1:8788`, with `allowLoopbackHttp: true`.
4. OpenResty -> the exact HTTPS upstream hostname using strict certificate validation, SNI and a CA trust file.

Use this corresponding (operator-private) Node config:

```yaml
tenant: local
service: api
publicHosts: [api.example.com]
policyFile: /etc/shield/rules.yaml
routes:
  - path: /health
    methods: [GET, HEAD]
    authenticated: false
    body: none
origin: http://127.0.0.1:8788
allowedOrigins: [http://127.0.0.1:8788]
originTokenEnv: SHIELD_ORIGIN_TOKEN
allowLoopbackHttp: true
listen: { host: 127.0.0.1, port: 8787 }
decisions: { kind: sqlite, path: /var/lib/shield/decisions.db }
```

Set `SHIELD_ORIGIN_TOKEN` and `EDGESHIELD_ORIGIN_TOKEN` to the **same strong randomly generated value** and do not log them. In a private configuration directory, set the other `EDGESHIELD_NGINX_*`, `EDGESHIELD_BRIDGE_PORT`, `EDGESHIELD_INGRESS_PORT`, `EDGESHIELD_ENGINE_PORT`, `EDGESHIELD_UPSTREAM_HOST`, `EDGESHIELD_UPSTREAM_PORT`, `EDGESHIELD_UPSTREAM_CA_FILE`, `EDGESHIELD_PUBLIC_HOST`, `EDGESHIELD_TLS_CERT_FILE` and `EDGESHIELD_TLS_KEY_FILE` environment variables. The renderer validates all values and writes a new owner-only `0600` config.

```sh
node deploy/openresty/render.mjs /etc/shield/private-nginx.conf
sudo nginx -t -c /etc/shield/private-nginx.conf
# Operator controls how/when the process is started.
```

**Verification (Linux with nginx, openssl and Node installed):**

```sh
node deploy/openresty/test-integration.mjs
```

The script generates temporary local test certificates, runs real NGINX with a simulated EdgeShield component, exercises an authenticated HTTPS origin, a blocking policy result, and forged-header rejection, then removes its temporary data. This is not proof of Cloudflare account deployment, actual Keyless SSL configuration or real production origin isolation.

**Security boundaries:** Do not bind the bridge or EdgeShield's HTTP listener publicly. The origin must verify its independent origin credential, and the origin must not remain publicly bypassable. Never accept arbitrary X-Forwarded-For values as trustworthy client identities. Dynamic TLS keyless functionality belongs to the cloud provider, not the npm package.
