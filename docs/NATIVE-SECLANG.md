# EdgeShield native SecLang

The main runtime now accepts SecLang source directly: no conversion to Shield IR.
Unsupported directives and transforms fail the entire configuration at startup.

VPS config: set secLangFile: ../../rules/native.conf and REMOVE policyFile.
Cloudflare: set SECLANG to reviewed SecLang text and REMOVE POLICY.
Library: createShield({secLang: sourceText, ...}) is the native API.

The old createShield({policy}) remains an explicit legacy migration mode
for existing deployments; both cannot be configured simultaneously.

rules/native.conf is a focused eight-rule native baseline, not complete OWASP CRS.
rules/upstream/crs contains authentic upstream rules; full native execution
of that corpus is not yet supported. Strict loading intentionally rejects it.

The GitHub Action validates native rules, refreshes upstream archives and CVE
candidates, but never deploys an unreviewed Cloudflare or VPS policy.
Operator-owned allowlist IDs can be numeric or prefixed with sec-.
