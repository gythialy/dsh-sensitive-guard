/**
 * `/guard` slash command: status, runtime mode switches, and the opt-in PII
 * restore path. Commands execute against the agent without entering model
 * history; every returned string is count/config-only and never contains a
 * secret or a restored value.
 * @module dsh-sensitive-guard/commands/guard
 */
import { chmod, mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { CommandResult } from '@deepseek-ai/dsh-commands'
import type { GuardRuntime } from '../hooks/runtime.js'
import {
  modeText,
  restoreDisabledText,
  restoreExistsText,
  restoreInvalidText,
  restoreMissingText,
  restoreSuccessText,
  restoreUnknownText,
  restoreWriteFailedText,
  statusText,
  unknownCommandText,
} from '../messages.js'
import { expandHome } from '../util/paths.js'

/** Placeholder grammar minted by the PII pseudonymizer. */
const PII_PLACEHOLDER = /^\[\[PII_[A-Z0-9_]+_[0-9a-f]{8}\]\]$/

/** Write one restored value to an owner-only file, refusing to overwrite. */
export async function writeRestoreFile(target: string, value: string): Promise<string> {
  const resolved = path.resolve(expandHome(target))
  await mkdir(path.dirname(resolved), { recursive: true, mode: 0o700 })
  await writeFile(resolved, value, { mode: 0o600, flag: 'wx' })
  await chmod(resolved, 0o600)
  return resolved
}

function status(runtime: GuardRuntime): CommandResult {
  const config = runtime.config
  return {
    kind: 'success',
    text: statusText(
      {
        mode: config.mode,
        failClosed: config.failClosed,
        inputLevel: config.levels.input,
        outputLevel: config.levels.output,
        policyRules: runtime.policy.ruleCount,
        redactionRules: runtime.redactor.ruleCount,
        auditEnabled: config.audit.enabled,
        auditPath: config.audit.path,
        piiEnabled: config.pii.enabled,
        piiRestore: config.pii.restore,
      },
      runtime.locale(),
    ),
  }
}

function setMode(runtime: GuardRuntime, enabled: boolean): CommandResult {
  const mode = enabled ? 'enforce' : 'monitor'
  runtime.config.mode = mode
  runtime.audit.decision({
    tool: enabled ? '/guard on' : '/guard off',
    decision: 'allow',
    mode,
    action: 'allowed',
  })
  return { kind: 'success', text: modeText(mode, runtime.locale()) }
}

/**
 * Execute one `/guard` invocation. Exported for unit tests; the command
 * adapter only forwards `rawInput`.
 */
export async function runGuardCommand(
  runtime: GuardRuntime,
  rawInput: string,
): Promise<CommandResult> {
  const input = rawInput.trim()
  const tokens = input.length === 0 ? ['status'] : input.split(/\s+/)
  const verb = tokens[0] ?? 'status'

  if (verb === 'status') return status(runtime)
  if (verb === 'on') return setMode(runtime, true)
  if (verb === 'off') return setMode(runtime, false)

  if (verb !== 'restore') {
    return { kind: 'error', text: unknownCommandText(verb, runtime.locale()) }
  }

  const config = runtime.config
  const locale = runtime.locale()
  if (!config.pii.restore) return { kind: 'error', text: restoreDisabledText(locale) }

  const placeholder = tokens[1]
  const target = tokens[2]
  if (placeholder === undefined || target === undefined) {
    return { kind: 'error', text: restoreMissingText(locale) }
  }
  if (!PII_PLACEHOLDER.test(placeholder)) {
    return { kind: 'error', text: restoreInvalidText(locale) }
  }

  const value = runtime.redactor.restore(placeholder)
  if (value === undefined) return { kind: 'error', text: restoreUnknownText(locale) }

  try {
    const file = await writeRestoreFile(target, value)
    runtime.audit.decision({
      tool: '/guard restore',
      decision: 'allow',
      mode: config.mode,
      action: 'allowed',
      rule: 'pii-restore',
    })
    return { kind: 'success', text: restoreSuccessText(placeholder, file, locale) }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    return {
      kind: 'error',
      text:
        code === 'EEXIST'
          ? restoreExistsText(target, locale)
          : restoreWriteFailedText(target, locale),
    }
  }
}

/** Register the command when the host exposes the interactive command service. */
export function registerGuardCommands(ctx: Context, runtime: GuardRuntime): void {
  ctx.inject(['commands'], (commandCtx) => {
    commandCtx.commands.register({
      name: 'guard',
      description: 'Sensitive Guard status, runtime mode, and PII restore',
      input: { hint: '[status|on|off|restore <placeholder> <file>]' },
      handler: ({ rawInput }) => runGuardCommand(runtime, rawInput),
    })
  })
}
