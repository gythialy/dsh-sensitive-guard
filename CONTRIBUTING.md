# Contributing

## Setup

```bash
pnpm install --store-dir .pnpm-store
pnpm verify
```

Node `^22.19 || >=24`, pnpm 12. TypeScript sources live in `src/`; `lib/` is build output
and is not committed.

## Required checks

Every change must pass:

```bash
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm test:e2e
pnpm build
pnpm publint
```

`pnpm verify` runs them in order. Do not commit generated `lib/`, coverage, or local
stores.

## Change rules

- New detection or rule category: add positive **and** negative fixtures; use synthetic
  values only (never a live credential, token, or private key).
- Policy behaviour: cover precedence, monitor vs enforce, and the no-plaintext reason
  contract.
- Hook behaviour: add a fake-context integration test; assert whether `next()` was
  called on the spill short-circuit path.
- Redaction: keep idempotence and `value`/content reference preservation.
- Logging: never log matched text, full paths, secrets, or PII. Hash instead.
- Docs: update README status tables when a _planned_ capability becomes available.

## Commits and PRs

Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, ...). CI lints PR
commit subjects. Keep security-relevant changes in focused commits, and describe the
threat-model impact in the PR template.

## Release

- Dual-channel publishing (npmjs plus the GitHub Packages mirror) is described
  in [RELEASING.md](RELEASING.md).
- Publishing a GitHub Release (draft → Publish) triggers
  `.github/workflows/release.yml`. The workflow checks the tag against
  `package.json`, publishes `@r0cky20/dsh-sensitive-guard` to npmjs when
  `NPM_TOKEN` exists, republishes the same build to GitHub Packages as
  `@gythialy/dsh-sensitive-guard` with `GITHUB_TOKEN`, and uploads a version-free
  `dsh-sensitive-guard.tgz` plus `SHA256SUMS` to that release. The workflow does not
  create the release.
- Bump `version` in `package.json` and move the `CHANGELOG` entries out of
  `[Unreleased]` in the release commit.
- After the first release, land changes on `main` through pull requests; keep release
  commits limited to the version and changelog.

## Licensing

By contributing you agree that your contribution is licensed under Apache-2.0. Vendored
or derived code must retain its original copyright and license notice and be listed in
`THIRD_PARTY_NOTICES.md`.
