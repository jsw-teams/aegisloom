# Documentation map / 文档导航

This repo keeps runtime code at the root-level source directories to preserve TypeScript output paths and npm exports; the documentation is grouped by purpose.

- [Architecture](architecture/ARCHITECTURE.md) and [protocol profiles](architecture/PROTOCOLS.md)
- [Deployment](guides/DEPLOYMENT.md), [rules](guides/RULES.md), [backend standard](guides/BACKEND-STANDARD.md) and [cloud adapters](guides/CLOUD-ADAPTERS.md)
- [CVE automation](security/CVE-AUTOMATION.md), [threat intelligence](security/THREAT-INTELLIGENCE.md) and [threat model](THREAT-MODEL.md)
- [Migration and naming](MIGRATION.md), [delivery status](STATUS.md), [validation](VALIDATION.md), [ADR](ADR.md) and [source configuration](SOURCE-CONFIG.md)

Source tree:

- packages/: shared runtime, rules, controls, cache, learning, CLI and supporting modules
- adapters/: provider-specific runtime adapters
- integrations/: feeds, SBOM and rule converters
- api-shield-convert/: separately packaged converter
- deploy/: Cloudflare and standalone deployment profiles
- examples/: runnable samples and configuration
- tests/: automated regression coverage
- benchmarks/: performance investigations
- scripts/: developer and release automation
- .github/: CI, Dependabot and dependency maintenance

Repository standards (README, SECURITY, CONTRIBUTING, LICENSE and NOTICE) remain at the root for GitHub discovery.
