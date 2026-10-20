# dsh-sensitive-guard

🇬🇧 English · 🇨🇳 [简体中文](README.zh-CN.md)

[![CI](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A host-only security plugin for [DeepSeek Harness](https://github.com/deepseek-ai/dsh): it **blocks credential reads and outbound secrets**, and **redacts secrets, tokens, and PII** before they reach the model, the session log, or a spill file.

> Status: **0.2.0**. The interception, redaction, and opt-in egress layers are implemented and tested. Remaining work is tracked in GitHub Issues (see [Roadmap](#roadmap)); do not describe planned capabilities as available.

## What it covers

| #   | Leak path                           | Coverage                                                                          |
| --- | ----------------------------------- | --------------------------------------------------------------------------------- |
| 1   | User paste → model request          | ✅ `agent/pre-step` (the committed `user/message` is redacted too)                |
| 2   | Tool read → model                   | ✅ `tools/pre-execute` path/argv/URL gate + `tools/post-execute` result redaction |
| 3   | Tool result → spill file            | ✅ post-execute short-circuits downstream policies on a hit                       |
| 4   | PTC sub-call log copy               | ✅ `tools/ptc-dispatch-log`                                                       |
| 5   | System prompt / runtime context     | ✅ `system-prompt/assemble`                                                       |
| 6   | Session inbox original              | ⚠️ partial: `agent/inbox/spliced` keeps the user's original text                  |
| 7   | Assistant repetition                | ❌ no public rewrite hook                                                         |
| 8   | Images / screenshots                | ❌ no OCR                                                                         |
| 9   | Third-party plugins / MCP internals | ❌ outside the DSH tool pipeline                                                  |
| 10  | Model-provider retention            | ❌ contractual choice, not a plugin concern                                       |

Content layers only constrain traffic that traverses DSH's tool and message pipelines. The opt-in egress guard (`egress.enabled`) adds destination-level control for child processes that honour `HTTPS_PROXY`: it enforces where connections may go, not what they carry, and deliberately does not intercept TLS.

## Features

- **Two layers**: a fail-closed allow/deny/ask gate and a redaction layer.
- **Five hooks**: pre-step, pre-execute, post-execute, PTC dispatch log, system-prompt assembly.
- **Rules**: user YAML rules + generated path policy + a vendored high-risk baseline (destructive commands, RCE, credential paths).
- **Detection**: tiered secret rules (PEM, provider keys, JWTs, URL credentials, assignments) and PII (email, phone, CN ID, card with Luhn, SSN) plus a high-entropy fallback.
- **Stable placeholders**: secrets use `[SECRET:<category>:<id>]` (one-way); PII uses keyed `[[PII_<TYPE>_<hash8>]]` (stable across sessions).
- **Audit**: JSONL with rule ids, counts, and hashes only — never plaintext, secrets, or full paths.
- **Observe first**: `mode: monitor` audits without blocking.
- **Optional notice**: `redact.notify` appends one count-only message when a step is redacted.

## Roadmap

All planned work is tracked in GitHub Issues. Start with the
[roadmap label](https://github.com/gythialy/dsh-sensitive-guard/issues?q=is%3Aissue+is%3Aopen+label%3Aroadmap);
the issue list is the single source of truth.

## Requirements

- Node.js `^22.19.0 || >=24.0.0`
- DeepSeek Harness `0.2.1-rc.2` (peer range `>=0.2.1-rc.2 <0.3.0-0`)
- A profile with the `tools` service (base bundle)

## Install

### From npm

Published to npmjs from v0.2.0 (anonymous, no token):

```bash
dsh plugin --profile web add @r0cky20/dsh-sensitive-guard
```

### From GitHub Release

For a pinned or checksum-verified artifact: verify the download against the
`SHA256SUMS` asset from the same release, then install:

```bash
dsh plugin --profile web add \
  https://github.com/gythialy/dsh-sensitive-guard/releases/latest/download/dsh-sensitive-guard.tgz
```

Both channels are public. Do not install the `@gythialy/dsh-sensitive-guard`
mirror from GitHub Packages; that registry needs GitHub auth and is not the
user-facing path.

### Agent-assisted install

Point a coding agent at [docs/agent-install.md](docs/agent-install.md), or give
it this prompt:

> Install dsh-sensitive-guard into my DSH web profile by following
> https://github.com/gythialy/dsh-sensitive-guard/blob/main/docs/agent-install.md

The guide covers the single install command, verification, restart, optional
`enforce` configuration, and rollback.

### From source (development)

```bash
# from the repository root
pnpm install
pnpm verify

# link the checkout into one profile; this writes ~/.dsh and needs approval
dsh plugin --profile web add link:"$PWD"
```

The package ships `cordis.patch.yml` via `dsh.bundle.patch`, so the plugin row mounts automatically. A profile-level override can replace its config by row id `sensitive-guard`:

```yaml
# ~/.dsh/profiles/web/cordis.patch.yml
- id: sensitive-guard
  name: '@r0cky20/dsh-sensitive-guard'
  config:
    mode: monitor
    levels:
      input: aggressive
      output: balanced
```

Restart `dsh web` after installing. Do not restart the GUI from inside a running session.

## Configure

```yaml
mode: monitor # monitor = audit only; enforce = block/ask
defaultDecision: allow # see the caution below
failClosed: true
redact:
  userMessages: true
  toolResults: true
  systemPrompt: true
  ptcLog: true
  notify: false # count-only notice after a redacted step
levels:
  input: aggressive # user/context messages
  output: balanced # tool results and system prompt
policy:
  rulesFile: .dsh/rules.yaml # resolved from the session cwd
  builtin: true
  maxRules: 256
paths:
  deny: ['**/.env', '**/.ssh/**', '**/*.pem', ...]
  allow: ['**/.env.example', '**/.env.sample', '**/.env.template']
network:
  enabled: true
  default: ask
egress: # opt-in destination-level guard; off by default
  enabled: false
  port: 41999
  failClosed: true
  unknown: allow
  allow: []
  deny: ['169.254.169.254:80', 'metadata.google.internal']
  upstream: ''
  canary: true
pii:
  enabled: true
  keyFile: '' # default: $DSH_HOME/sensitive-guard-pii.key
limits:
  maxScanBytes: 4194304
  maxArgsBytes: 131072
audit:
  enabled: true
  path: ~/.dsh/audit/sensitive-guard.jsonl
  rotateBytes: 5242880
```

> **`defaultDecision` caution.** The schema default is `ask`, matching the design document. With `mode: enforce`, a call that matches **no** rule therefore asks for approval. Run `monitor` first, review the audit log, then either set `defaultDecision: allow` or add explicit allow rules. In `monitor` the value does not affect behaviour.

Project rules live in `<project>/.dsh/rules.yaml`; see [docs/rules-format.md](docs/rules-format.md) and [docs/examples/rules.yaml](docs/examples/rules.yaml). Credential paths default to `deny` in enforce mode; `.env.example`, `.env.sample`, and `.env.template` are allowed.

PII key file: 32 random bytes, created with mode `0600` (parent `0700`). If it is unavailable the guard still works with a process-only key, but placeholders stop being stable across restarts.

### `/guard` commands

- `/guard status` — mode, levels, rule counts, audit state, PII/restore state; no secrets or matched values.
- `/guard on` / `/guard off` — switch `enforce`/`monitor` for this process only; not persisted.
- `/guard restore <placeholder> <file>` — requires `pii.restore: true`; writes the original PII to a new `0600` file, refuses to overwrite, and never echoes the value. The restore map is memory-only, so only placeholders minted in this process after enabling restore can be resolved. Secrets remain irreversible.
- `/guard egress [status|canary|report]` — opt-in egress guard state: listener, whether `https_proxy` points at it, rule counts, tunnel/blocked/byte counters, recent destinations, a loopback canary probe, and `report` (aggregated destinations from the audit log, with `--since 7d` and `--yaml`).

### Egress guard (opt-in)

v2 adds a destination-level CONNECT guard on DSH's existing `HTTPS_PROXY`
seam — host and port only, no TLS interception, no CA. It is off by default and
must be wired from the launch environment:

```bash
# $DSH_HOME/.env (or exported before launch), then restart DSH
https_proxy=http://127.0.0.1:41999
```

```yaml
egress:
  enabled: true
  port: 41999
  unknown: allow # allow-with-audit; use deny for an allowlist
  deny: ['169.254.169.254:80', 'metadata.google.internal', 'upload.example.com:443']
```

Coverage is honest, not universal: loopback is always bypassed by DSH,
telemetry and PTC/workflow workers stay direct, and JVMs, rustls, static Go,
containers, SSH, and HTTP/3 ignore or bypass proxy variables. A refused tunnel
returns `403` with `X-Guard-Reason`. See
[docs/configuration.md](docs/configuration.md#egress) for the full contract.

Approval prompts name the tool, a short risk category (for example `high-risk command` or `sensitive path`), and a redacted action summary; secrets are replaced and URL credentials are masked. Deny reasons state the block and one safe next step. `/guard status` prints a labeled block instead of `key=value` lines. Guard messages follow the DSH language setting (`en` / `zh`); an absent setting falls back to the process locale, then English.

## Scan

The package ships a standalone scanner that reuses the same rule table and
prints only categories, relative paths, counts, and line numbers:

```bash
pnpm build
node bin/scan.mjs --staged          # staged files in the current repository
node bin/scan.mjs src test          # explicit paths
node bin/scan.mjs --json --no-exit-code .
```

Exit codes: `0` clean, `1` findings, `2` usage/IO error. Files larger than
`--max-bytes` (default 8 MiB) and binary files are skipped. Matched values are
never printed.

## Audit

```json
{"ts":1760000000000,"phase":"decision","tool":"read","decision":"deny","rule":"config-deny:0","mode":"enforce","action":"blocked","pathHash":"ab12...","argsHash":"3f9a..."}
{"ts":1760000000001,"phase":"redact","tool":"bash","category":"aws-access-key","count":1,"placeholderIds":["7Q2F"],"spillBypassed":true}
```

The directory is `0700`, the file `0600`, and rotation keeps five `.1`–`.5` files. A write failure disables auditing with one warning; it never breaks a tool call.

## Privacy and limits

- The guard cannot rewrite DSH's `agent/inbox/spliced` receipt or assistant output; both are documented gaps.
- Session logs written before installation are not rewritten.
- Secrets in tool **arguments** are blocked, not rewritten: the host logs arguments before `tools/pre-execute`.
- The egress guard is opt-in and destination-level: it only covers clients that honour `https_proxy`, and only `host:port` is visible for HTTPS. Loopback, telemetry, PTC/workflow workers, JVMs, rustls, static Go, containers, SSH, and raw sockets bypass it; there is no CA and no TLS interception. See [docs/configuration.md](docs/configuration.md#egress) and the design note in [docs/sensitive-guard-integration.md](docs/sensitive-guard-integration.md). No OCR, no image redaction.
- Redaction is privacy-first; a false positive can remove benign text. Start in `monitor` and review.

## Development

```bash
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm test:coverage
pnpm test:e2e   # disposable headless profile + local mock provider
pnpm build
pnpm pack:check
```

`src` is TypeScript, built 1:1 into `lib` (no bundler) so published code is auditable. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. The rule baseline is derived from `dsh-permission-rules` (Apache-2.0, Copyright 2026 PerryLink); the secret rule table is derived from `dsh-secret-scrub` (MIT, Copyright (c) 2026 jkt-check). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [docs/sensitive-guard-integration.md](docs/sensitive-guard-integration.md).

Security reports: [SECURITY.md](SECURITY.md).
