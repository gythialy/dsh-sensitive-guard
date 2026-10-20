/**
 * `tools/pre-execute` arm: evaluate path, argv, parameter, and URL rules before
 * dispatch. Waterfall order is outermost-first; a denial returns without
 * delegating, while monitor mode only audits and continues.
 * @module dsh-sensitive-guard/hooks/pre-execute
 */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-tools'
import type { JsonValue, PolicyDecision } from '../contracts.js'
import { inspectArguments } from '../argguard/inspect.js'
import {
  EVALUATION_FAILURE_REASON,
  approvalPrompt,
  approvalReason,
  denyReason,
  formatBytes,
  type Risk,
  type RiskKind,
} from '../messages.js'
import { hashJson, hashPath } from '../util/hash.js'
import { agentKindOf, sessionIdOf, type GuardRuntime } from './runtime.js'

const HIGH_RISK_TAGS = new Set([
  'destructive',
  'privilege',
  'host-control',
  'git',
  'remote-code-execution',
  'fork-bomb',
])

function riskWith(kind: RiskKind, detail: string | undefined): Risk {
  return detail === undefined ? { kind } : { kind, detail }
}

/** Map internal evidence to the short risk category shown in prompts. */
function riskFor(args: {
  decision: PolicyDecision
  tooLarge: boolean
  hasSecret: boolean
  maxArgsBytes: number
}): Risk {
  if (args.tooLarge) {
    return {
      kind: 'arguments-too-large',
      detail: 'The serialized arguments exceed the ' + formatBytes(args.maxArgsBytes) + ' limit.',
    }
  }
  if (args.hasSecret) return { kind: 'secret-in-arguments' }

  const decision = args.decision
  if (decision.failure === true) return { kind: 'evaluation-failed' }
  if (decision.network === true) {
    return {
      kind: decision.ruleId === 'network:userinfo' ? 'embedded-credentials' : 'credential-query',
    }
  }

  const tags = decision.tags ?? []
  if (decision.ruleId?.startsWith('config-deny:') === true || tags.includes('sensitive-path')) {
    return riskWith('sensitive-path', decision.reason)
  }
  if (tags.some((tag) => HIGH_RISK_TAGS.has(tag))) {
    return riskWith('high-risk-command', decision.reason)
  }
  if (decision.paths !== undefined && decision.paths.length > 0) {
    return riskWith('sensitive-path', decision.reason)
  }
  if (decision.command !== undefined) {
    return riskWith('high-risk-command', decision.reason)
  }
  if (decision.matched) return riskWith('policy-approval', decision.reason)
  return { kind: 'default-approval' }
}

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
          failure: true,
          reason: EVALUATION_FAILURE_REASON,
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

      const risk = riskFor({
        decision,
        tooLarge,
        hasSecret,
        maxArgsBytes: config.limits.maxArgsBytes,
      })

      if (effectiveAction === 'deny') {
        audit.decision({ ...record, action: 'blocked' })
        return { kind: 'deny', reason: denyReason(exec.name, risk) }
      }

      if (effectiveAction === 'ask') {
        audit.decision({ ...record, action: 'asked' })
        return {
          kind: 'ask',
          reason: approvalReason(exec.name, risk),
          displayReason: approvalPrompt(exec.name, risk),
        }
      }

      audit.decision({ ...record, action: 'allowed' })
      return next()
    },
    { prepend: true },
  )
}
