/**
 * dsh-sensitive-guard — a host-only DeepSeek Harness plugin with two layers:
 * an interception gate on `tools/pre-execute` and redaction on every path that
 * carries content to the model, the session log, or a spill file.
 * @module dsh-sensitive-guard
 */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-system-prompt'
import type {} from '@deepseek-ai/dsh-tools'

import { AuditLog } from './audit.js'
import { registerGuardCommands } from './commands/guard.js'
import { resolveConfig, type GuardConfig } from './config.js'
import type { Logger } from './contracts.js'
import { registerPostExecute } from './hooks/post-execute.js'
import { registerPreExecute } from './hooks/pre-execute.js'
import { registerPreStep } from './hooks/pre-step.js'
import { registerPtcLog } from './hooks/ptc-log.js'
import { registerSystemPrompt } from './hooks/system-prompt.js'
import type { GuardRuntime } from './hooks/runtime.js'
import { createPolicyEngine } from './policy/index.js'
import { createRedactor } from './redact/index.js'
import { safeLogger } from './util/logger.js'

export { Config, resolveConfig, type GuardConfig } from './config.js'
export type { AuditLog } from './audit.js'
export { createPolicyEngine } from './policy/index.js'
export { createRedactor, createPseudonymizer } from './redact/index.js'

/** Plugin id used by the bundle patch and by owner-scoped diagnostics. */
export const name = 'sensitive-guard'

/** The interception and redaction layers both need the tool registry. */
export const inject = ['tools']

/**
 * Cordis entry point. Construction is eager and fail-loud: an invalid rule or
 * regex prevents activation instead of silently running without protection.
 *
 * @param ctx - plugin context; every listener is disposed with it.
 * @param config - validated row config from the bundle patch (or a test).
 */
export function apply(ctx: Context, config?: GuardConfig): void {
  const settings = resolveConfig(config)
  const logger = safeLogger(ctx.logger as unknown as Partial<Logger> | undefined)

  const redactor = createRedactor({
    config: settings,
    ...(settings.pii.keyFile.length > 0 ? { keyPath: settings.pii.keyFile } : {}),
    logger,
  })
  const policy = createPolicyEngine({ config: settings })
  const audit = new AuditLog({
    enabled: settings.audit.enabled,
    path: settings.audit.path,
    rotateBytes: settings.audit.rotateBytes,
    logger,
    cwd: process.cwd(),
  })

  const runtime: GuardRuntime = { config: settings, redactor, policy, audit, logger }
  registerPreStep(ctx, runtime)
  registerPreExecute(ctx, runtime)
  registerPostExecute(ctx, runtime)
  registerPtcLog(ctx, runtime)
  registerSystemPrompt(ctx, runtime)
  registerGuardCommands(ctx, runtime)

  logger.info(
    `sensitive-guard: active in ${settings.mode} mode ` +
      `(${policy.ruleCount} policy rules, ${redactor.ruleCount} redaction rules)`,
  )
}
