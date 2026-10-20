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

egress:
  enabled: false
  port: 41999
  failClosed: true
  unknown: allow
  allow: []
  deny:
    - '169.254.169.254:80'
    - 'metadata.google.internal'
  upstream: ''
  canary: true

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

| Field          | Default | Hook                                                  |
| -------------- | ------- | ----------------------------------------------------- |
| `userMessages` | `true`  | `agent/pre-step`                                      |
| `toolResults`  | `true`  | `tools/post-execute`                                  |
| `systemPrompt` | `true`  | `system-prompt/assemble`                              |
| `ptcLog`       | `true`  | `tools/ptc-dispatch-log`                              |
| `notify`       | `false` | append one count-only plugin notice per redacted step |

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
- `enabled: false` disables these checks. These URL heuristics are separate
  from the opt-in `egress` listener below.

### `egress`

Opt-in destination-level egress guard (ADR D4b). Off by default; it fills the
`HTTPS_PROXY` seam DSH's launcher already installs before any plugin loads, so
enabling it without wiring the environment protects nothing.

- `enabled`: bind a loopback CONNECT + plain-HTTP forward proxy on
  `127.0.0.1:<port>`. Never a wildcard address.
- `port` (default `41999`): fixed, because DSH resolves the proxy environment
  once at launch. A taken port fails the mount instead of silently moving.
- `failClosed` (default `true`): when the listener cannot bind, plugin mount
  fails. Set it to `false` only if you accept running without egress coverage.
- `unknown` (default `allow`): decision for a destination that matches no entry.
  `allow` keeps the guard quiet and auditable while you collect a deny list;
  `deny` turns `allow` into an allowlist.
- `allow` / `deny`: entries are `host`, `host:port`, or a glob in the host
  position (`*.example.com`). IPv6 must be bracketed (`[::1]:443`); an
  unbracketed address is dropped because it is ambiguous with `host:port`.
  `deny` is evaluated before `allow`, and an unparseable entry is dropped rather
  than matched loosely.
- `upstream`: optional `http://host:port` to chain CONNECT tunnels through (for
  a corporate proxy).
- `canary`: probe the listener once at mount and record the result.

Wire it from the launch environment, then restart DSH:

```bash
# $DSH_HOME/.env, or exported before launch
https_proxy=http://127.0.0.1:41999
# optional: only clients that speak plain HTTP
http_proxy=http://127.0.0.1:41999
```

Verify with `/guard egress status` (does the live value point at this listener?)
and `/guard egress canary` (does a real CONNECT tunnel echo?). A canary "denied"
result usually means `127.0.0.1` is in your `deny` list.

Bootstrap an allowlist from real traffic instead of guessing:

```text
/guard egress report              # last 7d, top destinations with counts
/guard egress report --since 24h  # narrower window
/guard egress report --yaml       # suggested egress.allow block to paste
```

The report reads the audit log and its rotations, aggregates `phase: "egress"`
connect records, and prints `host:port`, connect counts, and blocked counts.
Nothing is written to disk: `--yaml` is a suggestion to review and paste, not an
edit. Rolling `unknown` to `deny` is safe only after the report shows every host
the workflow legitimately needs.

What the guard sees: HTTPS shows `host:port` only (a CONNECT tunnel; no SNI
parsing, no CA); plain HTTP shows the request line, headers, and body, but the
audit log records only host, port, decision, rule, bytes, and duration. A
refused tunnel returns `403` with `X-Guard-Reason` —
`denied-by-rule`, `unknown-destination-blocked`, `invalid-target`, or
`upstream-failure` — and `X-Guard-Rule` when a rule matched. There is no
interactive `ask`: a tunnel has no session context, and a held handshake is a
hang.

Known blind spots — by design, not bugs:

- DSH always bypasses loopback, so a plugin posting to a local collector is not
  covered.
- Telemetry posts through `node:http` and ignores the proxy environment.
- PTC runtimes and workflow workers receive no proxy settings.
- Node 22.19/22.20 children honour `NODE_USE_ENV_PROXY` only from 22.21/24.
- JVMs, rustls (`webpki-roots`), static Go, and containers carry their own trust
  or proxy handling; SSH, raw sockets, and HTTP/3 are outside any HTTP proxy.
- No TLS interception and no CA (ADR D4c fixed for v2): HTTPS paths and bodies
  stay invisible at this layer. Body-aware policy remains in the tool pipeline,
  where the content is already plaintext.
- The guard is not a sandbox: a plugin can open a socket directly.

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
