# Configuration

The plugin row config is validated by `schemastery`; an invalid value fails
activation loudly. Defaults are shown below.

```yaml
mode: monitor
defaultDecision: ask
failClosed: true

redact:
  userMessages: true
  toolResults: true
  systemPrompt: true
  ptcLog: true
  notify: false

levels:
  input: aggressive
  output: balanced

policy:
  rulesFile: .dsh/rules.yaml
  builtin: true
  maxRules: 256

paths:
  deny:
    - '**/.env'
    - '**/.env.*'
    - '**/.ssh/**'
    - '**/.aws/**'
    - '**/.gnupg/**'
    - '**/.kube/**'
    - '**/.npmrc'
    - '**/.netrc'
    - '**/*.pem'
    - '**/*.key'
    - '**/id_rsa*'
    - '**/id_ed25519*'
    - '**/.dsh/.credentials.yaml'
  allow:
    - '**/.env.example'
    - '**/.env.sample'
    - '**/.env.template'

network:
  enabled: true
  default: ask

pii:
  enabled: true
  keyFile: ''
  restore: false

limits:
  maxScanBytes: 4194304
  maxArgsBytes: 131072

audit:
  enabled: true
  path: ~/.dsh/audit/sensitive-guard.jsonl
  rotateBytes: 5242880
```

## Fields

### `mode`

- `monitor` (default): every `deny`/`ask` decision is audited with
  `action: monitored`, then the call proceeds. Redaction still applies.
- `enforce`: `deny` blocks, `ask` requests approval, redaction applies.

Start with `monitor` for a few days. Review `~/.dsh/audit/sensitive-guard.jsonl`,
then switch to `enforce` after adding allow rules for legitimate workflows.

### `defaultDecision`

Decision when no rule matches: `ask` (default), `allow`, or `deny`.

> In `enforce`, the default `ask` asks for approval on every call that matches no
> rule. Set `allow` once you have reviewed the monitor data, or add explicit
> allow rules. `monitor` ignores this value.

### `failClosed`

When `true` (default), evaluation or redaction failures deny/withhold instead
of passing content through. Keep it true.

### `redact`

| Field          | Default | Hook                      |
| -------------- | ------- | ------------------------- |
| `userMessages` | `true`  | `agent/pre-step`          |
| `toolResults`  | `true`  | `tools/post-execute`      |
| `systemPrompt` | `true`  | `system-prompt/assemble`  |
| `ptcLog`       | `true`  | `tools/ptc-dispatch-log`  |
| `notify`       | `false` | planned count-only notice |

Disabling a hook removes that protection. The audit log still works for the
remaining hooks.

### `levels`

| Level        | Active tiers                                        |
| ------------ | --------------------------------------------------- |
| `minimal`    | tier 0: PEM, provider tokens, JWTs, URL credentials |
| `balanced`   | tiers 0–1: plus assignments and cloud credentials   |
| `aggressive` | tiers 0–2: plus PII and high-entropy fallback       |

`input` applies to user/context messages (default `aggressive`).
`output` applies to tool results and system prompt (default `balanced`).
PII rules are also gated by `pii.enabled`.

### `policy`

- `rulesFile`: project rule file, resolved from the session working directory.
  Missing file is not an error. Invalid YAML or an invalid rule shape fails
  evaluation (blocked by `failClosed`).
- `builtin`: append the vendored high-risk baseline after user and generated
  rules.
- `maxRules`: upper bound on the merged rule set; exceeding it is an error.

### `paths`

Generated rules appended after the user rule file:

1. `allow` entries (`**/.env.example` etc.) win over `deny` entries;
2. `deny` entries cover credential-bearing files;
3. the built-in baseline runs last.

User rules override generated rules. See [rules-format.md](rules-format.md) for
precedence details.

### `network`

URLs in `url`/`uri`/`endpoint` arguments and in shell commands are inspected.

- URL userinfo (`scheme://user:pass@host`) is denied.
- Query parameter names matching
  `token|key|secret|password|passwd|sig|signature|auth` use `network.default`.
- `enabled: false` disables these checks. No process-level proxy is used.

### `pii`

- `enabled`: include PII rules at the aggressive level.
- `keyFile`: empty means `$DSH_HOME/sensitive-guard-pii.key`. The file is 32
  random bytes, created atomically with mode `0600`; its directory is `0700`.
  If unavailable, a process-only key is used (placeholders are then not stable
  across restarts).
- `restore`: opt-in process-memory restore map for PII. When true,
  `/guard restore <placeholder> <file>` writes the original value to a new
  `0600` file (refusing to overwrite, never echoing it). Only placeholders
  minted after the option was enabled in this process can be resolved; the map
  is not persisted, and secrets remain irreversible.

### `limits`

- `maxScanBytes`: per-window cap for one regex pass. Larger text is scanned
  in UTF-8-aligned chunks (all bytes covered) and reported as truncated; a
  match straddling a chunk boundary triggers a single full-text fallback.
- `maxArgsBytes`: tool arguments larger than this are blocked/asked before
  execution.

### `audit`

- `enabled`, `path`, `rotateBytes`.
- Directory `0700`, file `0600`; rotation keeps `.1`–`.5`.
- Records contain rule ids, category counts, placeholder ids, and hashes —
  never plaintext, secrets, PII, or full paths.
- A write failure logs one warning and disables auditing; tool calls continue.

## Profile patch

```yaml
# ~/.dsh/profiles/web/cordis.patch.yml
- id: sensitive-guard
  name: '@gythialy/dsh-sensitive-guard'
  config:
    mode: monitor
    levels:
      input: aggressive
      output: balanced
    policy:
      rulesFile: .dsh/rules.yaml
      builtin: true
```

The package ships a bundle patch (`cordis.patch.yml`); a profile patch replaces
the row config by id.
