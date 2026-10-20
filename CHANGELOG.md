# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-20

### Added

- Opt-in destination-level egress guard (ADR D4b, design §6.6.1/§19.5): a
  zero-dependency loopback CONNECT + plain-HTTP forward proxy on
  `127.0.0.1:<egress.port>` that fills DSH's launch-time `HTTPS_PROXY` seam.
  `host`/`host:port` allow-deny with globs, unknown destinations default to
  allow-with-audit, cloud metadata endpoints are denied by default, `enforce`
  refuses to mount when the port cannot bind (`failClosed`), optional upstream
  chaining, and no certificate authority.
- `egress` audit phase (`mount`/`connect`/`close`/`deny`/`canary`/`error`)
  recording host, port, decision, rule id, bytes, and duration — never a path,
  header, or body.
- `/guard egress [status|canary]`: listener, live `https_proxy` wiring check,
  counters, recent destinations, and a loopback canary that proves the tunnel
  instead of claiming coverage.
- `/guard egress report [--since 7d] [--yaml]`: aggregates `phase: "egress"`
  connect records (active log plus rotations) into destination counts so an
  allowlist can be built from real traffic; `--yaml` prints a suggested
  `egress.allow` block without writing anything.
- Tests: policy, real-listener CONNECT and plain-HTTP forwarding, canary
  outcomes, upstream chaining, `apply()` mount/audit/dispose, a spawned
  `curl -x` allow/deny pair, and the audit report (windowing, rotations,
  malformed lines, YAML suggestion).
- Research notes in the design document: §19.6 records why per-child
  attribution is not reachable from a plugin (host support required), and §19.7
  records the gate and platform costs for any future TLS interception.
- Profile e2e for the guard (`test/e2e/egress.mjs`): a headless run with
  `http(s)_proxy` pointing at the guard lets the model call `bash`, proving the
  host-spawned child's request is proxied and audited; the deny variant proves
  the refusal and that the origin receives nothing. The listener no longer keeps
  a one-shot headless process alive.

### Changed

- Split package identity across the two registries: the canonical name is now
  `@r0cky20/dsh-sensitive-guard` for the GitHub Release tarball and npmjs, while
  the GitHub Packages mirror is republished as
  `@gythialy/dsh-sensitive-guard` because that registry requires the package
  scope to match the repository owner. A profile installed under the old
  `@gythialy` name must remove that plugin id before adding the new one.

## [0.1.1] - 2026-10-20

### Added

- Agent-oriented install guide (`docs/agent-install.md`) with a one-command
  tarball install, mount verification, restart guidance, optional `enforce`
  configuration, and rollback.
- v2 egress pre-research decision (design doc §19, ADR D4b–D4e): a
  destination-level CONNECT guard on DSH's existing `HTTPS_PROXY` seam, with
  TLS interception explicitly rejected for v2.

### Changed

- Refactored every guard-facing message into `src/messages.ts`: approval prompts
  now name the tool, risk category, and a redacted action summary; denial
  reasons add one safe next step; `/guard` uses a labeled status block; and
  startup, notice, and warning lines share one voice. No policy or audit
  behavior changed.
- Guard messages follow the DSH language preference (`en` / `zh`), with a
  process-locale fallback when the host preference is absent.
- Simplified install docs to the anonymous GitHub Release tarball; removed the
  GitHub Packages token walkthrough and the outdated "private by default"
  visibility step.

### Fixed

- CodeQL comparison alert in `src/action-summary.ts`: identify JSON-like records
  by object tag instead of comparing an already-narrowed value to `null`.

## [0.1.0] - 2026-10-20

### Added

- Repository scaffolding: Apache-2.0 license, third-party notices, CONTRIBUTING,
  SECURITY, issue/PR templates.
- pnpm + TypeScript build (`src` → `lib`, no bundler), oxlint/oxfmt, Vitest coverage.
- CI on Node 22/24, CodeQL, Dependabot, and a GitHub Release-driven publish workflow.
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
  GitHub Packages; npmjs remains deferred and tracked in #6.
- Release automation now starts from a human-created **published GitHub Release**
  instead of a tag push. The workflow validates the tag against `package.json`,
  publishes GitHub Packages with `GITHUB_TOKEN`, publishes npmjs only when
  `NPM_TOKEN` exists, and uploads `dsh-sensitive-guard.tgz` plus `SHA256SUMS` to
  the existing release. It never creates the release.

### Known limitations

- No process-level HTTP proxy.

## [0.0.0] - 2026-10-19

Initial repository initialization.
