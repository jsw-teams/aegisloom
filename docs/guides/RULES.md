# Shield IR v1 / 规则手册

Formal source: [schema.json](../../packages/rule-ir/schema.json). JSON and YAML represent the same IR.
Policies require `version: "1"` and a `rules` list. Rules require `id`, `name`, `service`, `when`,
and `then`. Other defaults are explicit in `loadPolicy`: enabled, priority 100, request-headers,
runtime-required, caching off, cache TTL 1m, community report off. Unknown keys, duplicate YAML keys,
aliases, unsafe property names, excessive complexity and conflicting IDs are rejected.

```yaml
version: "1"
rules:
  - id: protect-login
    name: 保护登录接口
    service: api
    when:
      path: /api/login
      method: POST
      requests:
        moreThan: 20
        within: 1m
        groupBy: verifiedClientIp
    then:
      action: rate-limit
      duration: 10m
```

The sugar above normalizes to AND path/method + a scoped fixed window. Request 21 is denied with
429 and a 10-minute penalty. Counters are per instance; no global IP identity is guessed from
headers. Missing verified grouping context fails closed. Stateful rules cannot use exact-request
decision caching. Window state is bounded; capacity exhaustion returns 503, never evicts live counters.

For predicates use `all: [...]`, `any: [...]`, `not: {...}`, or a leaf:

```yaml
field: query
key: operation
op: eq
value: delete
transforms: [urlDecode, trim, lowercase]
```

| Item | Semantics |
| --- | --- |
| Fields | path, method, header, query, body, identity, client.ip, client.class, risk.score |
| key | Required for header/query; body key is a JSON pointer and requires a JSON route |
| eq / contains / prefix | String comparisons; numbers use their string representation |
| exists | Explicit boolean `value`; missing is distinct from empty |
| range | Strict finite decimal syntax, inclusive min/max; missing or non-scalar never matches |
| regex | RE2JS substring match; max 256 pattern chars; no counted repetition, lookaround or backreferences |
| transforms | Ordered, at most 3: lowercase, trim, urlDecode. Invalid decoding rejects the request |
| query | URLSearchParams decoding occurs first; repeated values use ANY semantics |
| header | Web Headers normalized representation; raw field-line multiplicity is unavailable |
| body | Bounded UTF-8 text; JSON pointer matching requires request-body phase and strict JSON route |
| phases | request-headers/request-body execute in sorted priority after bounded body checks; response-headers is schema-defined but runtime unsupported |
| actions | block=403; detect emits and continues; rate-limit=429. challenge is schema-defined but runtime unsupported |
| score | A matching detect rule adds `then.score` to this request's trusted score (capped at 100); later rules can match risk.score |
| expiry | UTC ISO expiresAt; cache lifetime cannot exceed rule expiry; duration units ms/s/m/h, max 24h |
| placement | runtime-required/edge-preferred execute locally; edge-required requires confirmed L0 coverage and is refused by the standalone runtime; upstream-required refused |

Lower priority numbers execute first; ties sort by ID. Block/rate-limit terminate evaluation.
Identical same-scope predicates with equal priority and conflicting actions are rejected; general
logical overlap analysis is not implemented. Prefer explicit priorities. `community.report` is
intent metadata only and never uploads data; separate uploader consent is also required.

Validation and regression:

```sh
node dist/packages/cli/main.js validate examples/rules.yaml
node dist/packages/cli/main.js explain examples/rules.yaml
node dist/packages/cli/main.js simulate examples/rules.yaml examples/samples.json
node dist/packages/cli/main.js compatibility examples/rules.yaml
```

Simulation uses the actual runtime with an offline 204 origin and bounded decision store. It never
contacts the supplied sample URL. Samples must use `simulation.test`. For application contract/
identity tests, use the integration test harness with the real configured route list.

Control policy rollback saves validated immutable versions by SHA-256 and activates a previous hash.
Restart/reload runtimes explicitly; activation alone does not push a new policy into running isolates.

External rule reports enter through `integrations/rule-converter/importConversion`: only exact or
semantically equivalent runtime-only results with no limitations are accepted. Original bytes,
license allowlist, pinned version and per-rule source hashes must match. Partial/unsupported
reports are refused. The independent converter is installed/released separately.

中文：规则是声明式数据，不能执行 JavaScript、shell 或任意脚本。先做 Schema 与安全校验，
再用攻击及正常样本回归。云端不支持重要条件时必须拒绝部署，不会删条件后声称等价。
