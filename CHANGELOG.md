# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Repository scaffolding: Apache-2.0 license, third-party notices, CONTRIBUTING,
  SECURITY, issue/PR templates.
- pnpm + TypeScript build (`src` → `lib`, no bundler), oxlint/oxfmt, Vitest coverage.
- CI on Node 22/24, CodeQL, Dependabot, tag-driven release workflow.
- Configuration schema (`schemastery`) with monitor/enforce modes, fail-closed
  evaluation, redaction levels, path/network/PII limits, and audit settings.
- Policy engine: user YAML rules, generated path policy, vendored high-risk baseline,
  path normalization/symlink protection, argv tokenizer, parameter and network checks.
- Redaction engine: tiered secret/PII rules derived from `dsh-secret-scrub`, stable
  secret placeholders, keyed HMAC PII pseudonyms, false-positive filters.
- Hooks: `agent/pre-step`, `tools/pre-execute`, `tools/post-execute` (spill
  short-circuit), `tools/ptc-dispatch-log`, `system-prompt/assemble`.
- Hash-only JSONL audit with rotation.
- `/guard status|on|off|restore` commands, with an opt-in memory-only PII restore
  map that writes a new `0600` file and never echoes the value.
- `redact.notify`: one count-only plugin notice per redacted step.
- `bin/scan.mjs`: standalone repository/CI scanner with `--json`,
  `--staged`, `--max-bytes`, binary skipping, and masked output.
- End-to-end headless profile test with a disposable `DSH_HOME`, a linked plugin,
  a local OpenAI-compatible mock provider, and assertions on the provider request
  and audit log. Runs as `pnpm test:e2e` and in CI on Node 24.
- Unit and fake-context integration tests.

### Fixed

- Split the vendored `private-key-truncated` alternation into two
  same-category anchored rules (head and tail). Matching behavior, hit counts,
  and linear scanning cost are unchanged, and CodeQL's
  `js/regex/missing-regexp-anchor` operator-precedence alert is resolved.

### Changed

- README roadmap is now managed entirely in GitHub Issues; the status table was
  removed.
- Canonical package name is now `@gythialy/dsh-sensitive-guard`, required by GitHub
  Packages. The same build is distributed as a GitHub Release tarball and via
  GitHub Packages; npmjs remains deferred and tracked in #6. The release workflow no
  longer needs `NPM_TOKEN` and attaches `SHA256SUMS` to the release.

### Known limitations

- No process-level HTTP proxy.

## [0.0.0] - 2026-10-19

Initial repository initialization.
