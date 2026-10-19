import type { Agent } from '@deepseek-ai/dsh-agent'
import type {
  BlockLike,
  GuardAction,
  Logger,
  PolicyEngine,
  RedactionHit,
  Redactor,
} from '../contracts.js'
import type { GuardConfig } from '../config.js'
import type { AuditLog } from '../audit.js'

/** Shared, immutable services used by every hook. */
export interface GuardRuntime {
  config: GuardConfig
  redactor: Redactor
  policy: PolicyEngine
  audit: AuditLog
  logger: Logger
}

/** Session id for audit correlation; never the session content. */
export function sessionIdOf(agent?: Agent | undefined): string | undefined {
  const id = agent?.session?.id
  return id === undefined ? undefined : String(id)
}

/** The host presents subagents as separate sessions; map to the rule vocabulary. */
export function agentKindOf(agent?: Agent | undefined): 'main' | 'subagent' {
  return agent?.session?.header?.origin === 'subagent' ? 'subagent' : 'main'
}

/** Content blocks are structurally compatible with the guard's narrow view. */
export function asBlocks(content: readonly unknown[]): readonly BlockLike[] {
  return content as readonly BlockLike[]
}

/** Convert rewritten structural blocks back to the host's content type. */
export function asContent<T>(blocks: BlockLike[]): T {
  return blocks as unknown as T
}

/** Emit one redact audit record per category. */
export function recordRedactions(
  runtime: GuardRuntime,
  phase: 'pre-step' | 'post-execute' | 'ptc-log' | 'system-prompt',
  hits: readonly RedactionHit[],
  context: {
    session?: string | undefined
    tool?: string | undefined
    spillBypassed?: boolean
    truncated?: boolean
  },
): void {
  for (const hit of hits) {
    runtime.audit.redact({
      hook: phase,
      category: hit.category,
      count: hit.count,
      ...(context.session === undefined ? {} : { session: context.session }),
      ...(context.tool === undefined ? {} : { tool: context.tool }),
      ...(context.spillBypassed === true ? { spillBypassed: true } : {}),
      ...(context.truncated === true ? { truncated: true } : {}),
      ...(hit.placeholderIds === undefined ? {} : { placeholderIds: hit.placeholderIds }),
    })
  }
}

/** Human-readable action label for the audit record. */
export function auditAction(action: GuardAction): 'allowed' | 'blocked' | 'asked' {
  if (action === 'deny') return 'blocked'
  if (action === 'ask') return 'asked'
  return 'allowed'
}
