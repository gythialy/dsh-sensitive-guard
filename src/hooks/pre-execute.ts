/**
 * `tools/pre-execute` arm: evaluate path, argv, parameter, and URL rules before
 * dispatch. Waterfall order is outermost-first; a denial returns without
 * delegating, while monitor mode only audits and continues.
 * @module dsh-sensitive-guard/hooks/pre-execute
 */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '../contracts.js'
import { inspectArguments } from '../argguard/inspect.js'
import { hashJson, hashPath } from '../util/hash.js'
import { agentKindOf, sessionIdOf, type GuardRuntime } from './runtime.js'

const REDACTION_FAILED = 'sensitive-guard: policy evaluation failed; the call was blocked'

export function registerPreExecute(ctx: Context, runtime: GuardRuntime): void {
  const { config, policy, redactor, audit } = runtime

  ctx.on(
    'tools/pre-execute',
    async (exec, next) => {
      const session = sessionIdOf(exec.agent)
      const cwd = exec.agent?.session?.header?.cwd
      const argsHash = hashJson((exec.arguments ?? null) as JsonValue)

      let decision
      try {
        decision = policy.evaluate({
          tool: exec.name,
          args: exec.arguments,
          agentId: agentKindOf(exec.agent),
          ...(cwd === undefined ? {} : { cwd }),
          platform: process.platform,
        })
      } catch {
        decision = {
          action: config.failClosed ? ('deny' as const) : ('ask' as const),
          matched: true,
          reason: REDACTION_FAILED,
        }
      }

      // Arguments are already logged by the host before this hook runs, so the
      // only safe response to a secret here is to stop the call.
      let tooLarge = false
      let hasSecret = false
      if (decision.action === 'allow') {
        const inspection = inspectArguments(exec.arguments, redactor, config.limits.maxArgsBytes)
        tooLarge = inspection.tooLarge
        hasSecret = inspection.hasSecret
      }

      const effectiveAction = tooLarge
        ? config.failClosed
          ? 'deny'
          : 'ask'
        : hasSecret
          ? 'ask'
          : decision.action
      const reason = tooLarge
        ? 'sensitive-guard: tool arguments exceed the configured size limit'
        : hasSecret
          ? 'sensitive-guard: tool arguments contain a credential; remove it or ask the user'
          : decision.reason

      const monitored = config.mode === 'monitor' || decision.enforce === false
      const pathHash = decision.paths?.[0] === undefined ? undefined : hashPath(decision.paths[0])

      if (effectiveAction === 'allow' && !decision.matched && !tooLarge && !hasSecret) {
        return next()
      }

      const record = {
        tool: exec.name,
        decision: effectiveAction,
        mode: config.mode,
        ...(session === undefined ? {} : { session }),
        ...(decision.ruleId === undefined ? {} : { rule: decision.ruleId }),
        ...(pathHash === undefined ? {} : { pathHash }),
        argsHash,
      }

      if (monitored) {
        audit.decision({ ...record, action: 'monitored' })
        return next()
      }

      if (effectiveAction === 'deny') {
        audit.decision({ ...record, action: 'blocked' })
        return {
          kind: 'deny',
          reason: reason ?? 'sensitive-guard: blocked by policy',
        }
      }

      if (effectiveAction === 'ask') {
        audit.decision({ ...record, action: 'asked' })
        return {
          kind: 'ask',
          reason: reason ?? 'sensitive-guard: approval required',
          displayReason: {
            en: 'Sensitive Guard: this call may expose or transmit a credential.',
            zh: '敏感信息守卫：此调用可能读取或外发凭据，是否继续？',
          },
        }
      }

      audit.decision({ ...record, action: 'allowed' })
      return next()
    },
    { prepend: true },
  )
}
