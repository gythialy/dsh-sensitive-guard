# dsh-sensitive-guard

🇬🇧 English · 🇨🇳 [简体中文](README.zh-CN.md)

[![CI](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/gythialy/dsh-sensitive-guard/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A host-only security plugin for [DeepSeek Harness](https://github.com/deepseek-ai/dsh): it **blocks credential reads and outbound secrets**, and **redacts secrets, tokens, and PII** before they reach the model, the session log, or a spill file.

> Status: **0.0.0, pre-release**. The interception and redaction vertical slice is implemented and tested. Planned work is tracked in GitHub Issues (see [Roadmap](#roadmap)); do not describe planned capabilities as available.

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

The guard only constrains content that traverses DSH's tool and message pipelines.

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

### From GitHub Release (recommended)

No npm account or token is required. Verify the download against the
`SHA256SUMS` asset from the same release, then install:

```bash
dsh plugin --profile web add \
  https://github.com/gythialy/dsh-sensitive-guard/releases/latest/download/dsh-sensitive-guard.tgz
```

### From GitHub Packages

GitHub Packages requires a GitHub token even for public packages. Add the scope
and token to the DSH profile's `.npmrc`:

```ini
# ~/.dsh/profiles/web/.npmrc
@gythialy:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_TOKEN}
```

Use a classic PAT with `read:packages`, then:

```bash
dsh plugin --profile web add @gythialy/dsh-sensitive-guard
```

The package is private by default after the first publish; set it to public in
the package settings. Installation still requires the token.

### From npm (planned)

Tracked in [#6](https://github.com/gythialy/dsh-sensitive-guard/issues/6). The
future npmjs release will use the same scoped name.

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
  name: '@gythialy/dsh-sensitive-guard'
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
- No process-level HTTP/CONNECT proxy, no OCR, no image redaction in v1.
- Redaction is privacy-first; a false positive can remove benign text. Start in `monitor` and review.

## Development

```bash
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm test:coverage
pnpm build
pnpm pack:check
```

`src` is TypeScript, built 1:1 into `lib` (no bundler) so published code is auditable. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. The rule baseline is derived from `dsh-permission-rules` (Apache-2.0, Copyright 2026 PerryLink); the secret rule table is derived from `dsh-secret-scrub` (MIT, Copyright (c) 2026 jkt-check). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [docs/sensitive-guard-integration.md](docs/sensitive-guard-integration.md).

Security reports: [SECURITY.md](SECURITY.md).
