# Rule format

Project rules live in `<project>/.dsh/rules.yaml` (configurable via
`policy.rulesFile`), resolved from the session working directory.

```yaml
rules:
  - id: deny-env-read
    action: deny # allow | deny | ask
    priority: 100 # higher first; equal priorities keep declaration order
    match:
      tools: [read, grep, bash] # glob
      params: # top-level argument key -> globs
        file_path: ['**/.env', '**/.env.*']
      paths: ['**/.env', '**/.ssh/**'] # extracted from nested arguments
      argv: # bash/pwsh command decomposition
        command: cat
        anyArg: ['**/.env']
      agents: [main, subagent] # optional
      when:
        platform: [darwin, linux]
    reason: 'Reading credentials is blocked; use .env.example or ask the user.'
    enabled: true
    enforce: true # false = audit only for this rule
```

## Matching semantics

- Dimensions are **AND**ed; values inside one dimension are **OR**ed.
- A rule with no constraining dimension never matches.
- A rule matches only if the tool name, each requested parameter value, each
  path, the argv shape, platform, and agent condition all agree.
- Rules are sorted by `priority` descending; ties keep declaration order
  (`Array.sort` is stable). The first match wins.
- No match returns `defaultDecision` (default `ask`; see the caution in
  [configuration.md](configuration.md)).
- Per-rule `enforce: false` reports the match in the audit log but does not
  block or ask.
- `enabled: false` removes the rule entirely.

## Dimensions

### `tools`

Glob(s) matched against the host tool name (`read`, `bash`, `web_fetch`, ...).

### `params`

Top-level argument keys mapped to glob arrays. Scalar values are compared;
numbers and booleans are stringified. Example:

```yaml
params:
  file_path: ['**/.env']
  url: ['https://*.example.com/*']
```

### `paths`

Globs matched against every path-like value found in the arguments (keys
`path`, `file_path`, `filepath`, `file`, `dir`, `directory`, `target`).
Paths are expanded (`~`, whitelisted environment variables), resolved against
the session cwd, normalized, and matched both as-written and through
`realpathSync` when the file exists, so symlinks to credential files are
caught. Windows separators are normalized and matching is case-insensitive.

### `argv`

Available for shell tools. The lightweight tokenizer understands single/double
quotes, backslash escapes, `|`, `||`, `&&`, `;`, redirections, and leading
`sudo`/`env` prefixes. It never executes or expands anything. `bash -c "..."`
is parsed recursively (up to three levels). Shell signatures keep `(`, `)`,
and `|` literal: glob patterns support `*`, `?`, character classes, and brace
expansion, but **not** extglob/alternation. This is what lets the built-in
fork-bomb and `curl*|*sh` rules match their literal signatures.

| Field      | Meaning                                                                 |
| ---------- | ----------------------------------------------------------------------- |
| `command`  | glob for the command word                                               |
| `args`     | ordered glob prefix of the argument tokens                              |
| `anyArg`   | every token must match; a leading `!` is a negation that must NOT match |
| `pipeline` | glob against the normalized pipeline signature                          |

Example from the built-in baseline:

```yaml
argv:
  command: dd
  anyArg: ['of=/dev/*', '!of=/dev/null', '!of=/dev/zero']
```

### `agents`

`main` or `subagent`, derived from the session header, not a display name.

### `when.platform`

`darwin`, `linux`, `win32`, etc.

### `reason`

Model-facing text. **Never include a matched path, secret, or user data** — the
model sees this string. Put a generic, actionable explanation here; the audit
log stores hashes instead.

## Precedence and generated rules

The merged rule order is:

1. project rules (as declared; default priority `0`),
2. generated `allow` path rules (`config-allow:<n>`, effective priority `-10`),
3. generated `deny` path rules (`config-deny:<n>`, effective priority `-20`),
4. the built-in baseline (`builtin:<n>`, effective priority `-100`).

Higher priority wins, so project rules can override the defaults. Generated
allow rules beat generated deny rules, which is why `.env.example` stays
readable while `.env` is denied. The baseline adds destructive-command, RCE,
privilege-escalation, and credential-path rules.

## Built-in baseline

`src/policy/baseline.yaml` is vendored from
`dsh-permission-rules` 0.7.20 (Apache-2.0, Copyright 2026 PerryLink). See
`THIRD_PARTY_NOTICES.md`.

## Network rules

Network checks are configuration-driven (`network.enabled`,
`network.default`), not YAML rules in this version:

- URL with userinfo → `deny`;
- sensitive query parameter name → `network.default`;
- everything else → normal rule evaluation.

A process-level HTTP proxy and domain allow/deny lists are not implemented in
v1.
