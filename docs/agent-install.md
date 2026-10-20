# Agent install guide

This page is for an AI coding agent helping a user install
`dsh-sensitive-guard` into an existing DeepSeek Harness profile. Follow the
steps in order; do not improvise extra changes.

## 1. Confirm the environment

Run:

```bash
dsh --version
```

- If `dsh` is missing, stop and ask the user to install DeepSeek Harness first.
- Ask which DSH profile to use. If the user does not care and a `web` profile
  exists, use `web`.
- Installing writes under `~/.dsh`. If your host requires approval for writes
  outside the workspace, request it before the next step.

## 2. Install with one command

```bash
PROFILE="${DSH_PROFILE:-web}"
dsh plugin --profile "$PROFILE" add \
  https://github.com/gythialy/dsh-sensitive-guard/releases/latest/download/dsh-sensitive-guard.tgz
```

Use the **GitHub Release tarball**. Do not install from GitHub Packages and do
not ask the user for a registry token.

Expected result: the command reports the package as added and exits 0. The
plugin's `cordis.patch.yml` mounts the `sensitive-guard` row automatically.

## 3. Verify the mount

```bash
dsh --profile "$PROFILE" --dump-config | grep -A6 "id: sensitive-guard"
```

Expected row:

```yaml
- id: sensitive-guard
  name: '@gythialy/dsh-sensitive-guard'
  config:
    mode: monitor
```

If the row is missing, stop and report the exact command output; do not edit
DSH internals.

## 4. Tell the user to restart

The plugin loads when the profile boots. Ask the user to restart `dsh web` or
their TUI **outside the current session**. Never restart the GUI from inside a
running session.

## 5. Optional configuration

The default is safe observation: `mode: monitor` audits but does not block.
Only switch to `enforce` after the user explicitly asks.

Profile override: `~/.dsh/profiles/<profile>/cordis.patch.yml`

```yaml
- id: sensitive-guard
  name: '@gythialy/dsh-sensitive-guard'
  config:
    mode: enforce
```

Restart again after changing the patch. Do not weaken credential-path denial or
disable audit unless the user asks.

### Optional egress guard

Only when the user explicitly asks for destination-level egress control. This is
a two-part setup because the proxy value is a launch-time snapshot:

1. In `$DSH_HOME/.env`, add `https_proxy=http://127.0.0.1:41999`.
2. In the profile patch, set `egress: { enabled: true, port: 41999 }`.
3. Restart, then run `/guard egress canary`. A failing canary means the wiring is
   wrong — report the exact result instead of claiming coverage.

The default `egress.unknown: allow` (allow-with-audit) purposefully does not
block unknown destinations. Do not switch to `unknown: deny` or invent an
`allow` list on the user's behalf without an explicit host list from them.

## 6. Rollback

```bash
dsh plugin --profile "$PROFILE" remove @gythialy/dsh-sensitive-guard
```

Then ask the user to restart.

## Rules for the agent

- Never print or read secrets, tokens, private keys, or full credential paths.
- Do not install from `npm.pkg.github.com`; that registry needs GitHub auth and
  is not the user-facing path.
- Do not modify the repository checkout, commit, tag, or release anything for an
  install request.
- If a command fails, report the exact stderr and stop; do not retry with a
  different registry or elevated permissions.
- The Release tarball is stable at `releases/latest/download/dsh-sensitive-guard.tgz`;
  pin a version with `releases/download/v0.1.0/dsh-sensitive-guard.tgz` only if
  the user asks for a fixed version.

## One-line prompt for the user

```text
Install dsh-sensitive-guard into my DSH web profile by following
https://github.com/gythialy/dsh-sensitive-guard/blob/main/docs/agent-install.md
```
