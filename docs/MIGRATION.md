# ShieldWeave to AegisLoom / 迁移说明

The GitHub repository is renamed from jsw-teams/shieldweave to jsw-teams/aegisloom. GitHub normally redirects the old repository URL; update Git remotes and workflow references to the canonical path.

For existing users, the npm package ID @jsw-teams/shieldweave and executable shieldweave are intentionally retained until a separately coordinated package release. A second executable alias aegisloom points to the same CLI entrypoint. Library symbols (such as createShield) and configuration schemas are unchanged.

Documentation formerly at the project root is now organized under docs/architecture/, docs/guides/ and docs/security/. SECURITY.md and CONTRIBUTING.md stay at root.

For local Git clones: git remote set-url origin https://github.com/jsw-teams/aegisloom.git

No production deployments, npm publication or external consumers are automatically migrated by this repository-only refactor.
