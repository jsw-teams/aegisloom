# EdgeShield · 边缘盾迁移说明 / Migration

EdgeShield was formerly AegisLoom, originally ShieldWeave.

- Target GitHub repository name: `jsw-teams/edgeshield`. The exact rename must be performed by a repository administrator in GitHub Settings → General → Repository name; editing files alone will not change the repository URL.
- Target npm package: `@jsw-teams/edgeshield` (next planned release 2026.10.7). Building the tarball does not publish it; publishing requires permission to the npm `@jsw-teams` organization.
- New executable: `edgeshield`; legacy executable aliases `aegisloom` and `shieldweave` are included in the same new package for existing automation.
- Existing npm package installations, cloud Worker secrets, runtime policy and deployed origin TLS are **not** automatically changed.
- TypeScript exports (`createShield`, `SHIELD_VERSION`) and config keys remain compatible during transition.
- After GitHub rename, update local clone remotes: `git remote set-url origin https://github.com/jsw-teams/edgeshield.git`.
- Historical release URLs and existing commits are unchanged; published tags are immutable.

Rule updates: GitHub Actions automatically checks vetted source and official OWASP CRS source archives. `rules/active.json` is the **executable EdgeShield subset**. `rules/upstream/crs/*.conf` is **unconverted SecLang**, not activated by the EdgeShield runtime. Production rule deployment remains a separate, reviewed action.
