# EdgeAegis agent instructions

Vibe Coding and AI-assisted contributions are welcome. The submitting person or agent is responsible for understandable code, truthful evidence and reviewable scope. Read the root README before changing configuration or deployment behavior.

## Work and verification

- Fetch and inspect upstream before editing and again before pushing. Preserve unrelated edits, use the canonical checkout and never force-push.
- Keep the first-party SecLang parser and execution engine shared across adapters. Do not introduce ModSecurity, a replacement WAF engine, rule conversion or the historical IR.
- Missing files, unknown semantics, execution exhaustion and incomplete CRS compilation must fail visibly. Never skip rules, weaken tests or simulate responses to claim compatibility.
- Run relevant tests before uploading code. Engine, parser, rules and adapter changes require `npm run check`, `npm run test:crs`, `npm run cloudflare:dry-run` and `npm run audit`. Report commands, runtime, exact results and any checks not run. Documentation changes require validation of the affected commands, examples and links; explain inapplicable checks.
- Add regressions for reproduced security bugs. Test actual normal and malicious requests, chain/state semantics and affected adapter behavior. Do not rely only on assertions that mirror the implementation.
- Keep ordinary settings in configuration files and credentials in private deployment files. Never include real secrets, private origins or customer data in source, logs, recordings, fixtures, public examples or npm archives.
- Route internal businesses through the firewall entry point. Preserve platform isolation, independently keyed origins and trusted transport metadata. Do not add an unprotected business entry point.
- Prefer supervised background services for production over SSH. Do not start services during package installation or leave unrelated processes running.
- Use compatible published dependencies; do not retain lockfiles in this public engine repository. Publish only through the verified GitHub Actions Trusted Publisher workflow when authorized. Contribution verification does not authorize deployment, account changes or publication.

## Agent security reports

- Agents may submit reports. Sensitive findings go through the GitHub private vulnerability reporting link in README. If unavailable, request a private contact without publishing exploit details.
- Include affected version/commit and configuration, prerequisites, trust boundary, a minimal sanitized reproducer, expected and actual behavior, concrete impact, exact test commands/results and a regression test where possible.
- Label unverified hypotheses, environmental limitations and AI assistance. Consolidate duplicates; do not claim severity or exploitation without evidence.
- Test local/disposable environments or explicitly authorized targets only. Never attack production merely to validate a report; do not disclose credentials, customer payloads or working exploits for unfixed live deployments publicly.

## 中文协作规范

欢迎 Vibe Coding 与 Agent 贡献。先读 README，保留他人修改，先测试再上传。涉及引擎、规则或适配器时必须执行上述完整检查，准确注明结果和未验证项；禁止跳过 CRS 规则、伪造执行或削弱断言来制造通过率。敏感漏洞走私密报告，提供版本、前提、脱敏复现、影响与测试证据，明确区分事实和推测。生产部署、凭据变更和发包必须具有用户授权，提交安全报告本身不构成授权。
