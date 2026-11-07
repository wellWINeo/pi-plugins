# CI and npm publishing

CI runs on pull requests and pushes to `main` using Node.js 24 and `npm ci`, then runs the root typecheck, lint, and Vitest scripts.

## Trusted npm publishing setup

`.github/workflows/publish.yml` publishes when a pushed tag matches a plugin's exact `name@version` (for example `pi-secret-guard@0.1.0`) or `vversion` (for example `v0.1.0`). For a `v` tag, every plugin currently at that version is published. The workflow uses npm provenance and GitHub OIDC; it does not use an npm access token.

Before publishing, the owner must:

1. Ensure the npm account/organization owns the package and has enabled publishing for it. The plugin's `publishConfig.access` is `public`.
2. In GitHub repository Settings → Environments, create an environment named `npm`. Optionally restrict deployment to protected release tags/branches.
3. On npmjs.com, configure Trusted Publisher for each package: select GitHub Actions, enter this repository's owner and repository name, workflow filename `publish.yml`, and environment `npm`. Repeat for every package. No `NPM_TOKEN` secret or token-based `.npmrc` is needed.
4. Increment the plugin's `version`, commit the change, push the commit, and push a matching tag. npm package versions are immutable, so do not reuse a published version.

The publish job grants only `contents: read` and `id-token: write`, and updates npm to a current CLI for OIDC trusted publishing and provenance support.
