# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on
[gythialy/dsh-sensitive-guard](https://github.com/gythialy/dsh-sensitive-guard/security/advisories/new).
Do **not** open a public issue for an exploitable finding.

Include the plugin version, DSH version, mode (`monitor`/`enforce`), the affected
hook, and a minimal synthetic reproduction. Never include live credentials,
tokens, private keys, or personal data. Redact home paths and session ids.

## Supported versions

| Version               | Supported                  |
| --------------------- | -------------------------- |
| 0.1.x (after release) | ✅                         |
| < 0.1.0               | ❌ pre-release scaffolding |

## Threat model

The guard protects content that traverses DSH's tool and message pipelines:

- user messages admitted to a step (`agent/pre-step`);
- tool arguments (`tools/pre-execute`) and results (`tools/post-execute`);
- the durable copy of PTC sub-dispatch logs (`tools/ptc-dispatch-log`);
- assembled system prompt sections, runtime contexts, and variables (`system-prompt/assemble`).

It does **not** protect:

- the original text in `agent/inbox/spliced`;
- assistant output (no public rewrite hook);
- images or screenshots (no OCR);
- content read or sent by third-party plugins/MCP servers outside the DSH tool pipeline;
- provider-side retention;
- session logs written before the plugin was enabled.

Tool arguments are already logged by the host before `tools/pre-execute` runs, so
the guard can only **block** a call containing a credential, not rewrite the
already-recorded arguments.

## Security-relevant defaults

- `mode: monitor` by default; no blocking until explicitly enabled.
- `failClosed: true`: evaluation/redaction failures deny or withhold content.
- Credential paths (`.env`, `.ssh`, `.aws`, `.gnupg`, `.kube`, `*.pem`, `*.key`,
  `id_rsa*`, `id_ed25519*`, `.npmrc`, `.netrc`, DSH credentials) are denied in
  `enforce` mode.
- Audit records never contain plaintext, secrets, or full paths.
