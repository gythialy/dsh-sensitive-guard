/**
 * `tools/ptc-dispatch-log` arm: only the durable copy of a `run_code`
 * sub-dispatch is rewritten. The program already received the structured value,
 * and the model never sees this event.
 * @module dsh-sensitive-guard/hooks/ptc-log
 */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-tools'
import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import { asBlocks, asContent, recordRedactions, sessionIdOf, type GuardRuntime } from './runtime.js'

const WITHHELD = '[sensitive-guard] PTC log redaction failed; content withheld.'

export function registerPtcLog(ctx: Context, runtime: GuardRuntime): void {
  const { config, redactor, audit } = runtime
  if (!config.redact.ptcLog) return

  ctx.on(
    'tools/ptc-dispatch-log',
    async (dispatch, next) => {
      const session = sessionIdOf(dispatch.exec.agent)
      const level = config.levels.output
      try {
        const pre = redactor.redactBlocks(asBlocks(dispatch.content), level)
        if (pre.changed) {
          recordRedactions(runtime, 'ptc-log', pre.hits, {
            session,
            tool: dispatch.name,
            spillBypassed: true,
            ...(pre.truncated ? { truncated: true } : {}),
          })
          return asContent<ContentBlock[]>(pre.content)
        }

        const content = await next()
        const post = redactor.redactBlocks(asBlocks(content), level)
        if (!post.changed) return content
        recordRedactions(runtime, 'ptc-log', post.hits, { session, tool: dispatch.name })
        return asContent<ContentBlock[]>(post.content)
      } catch (error) {
        audit.error({
          tool: dispatch.name,
          ...(session === undefined ? {} : { session }),
          message: error instanceof Error ? error.name : 'redaction-error',
        })
        return [{ type: 'text', text: WITHHELD } as ContentBlock]
      }
    },
    { prepend: true },
  )
}
