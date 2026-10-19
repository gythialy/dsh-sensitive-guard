/**
 * `agent/pre-step` arm: redact every admitted message before it is committed
 * as `user/message` and sent to the model. The original prompt remains in the
 * `agent/inbox/spliced` event, which the plugin cannot rewrite.
 * @module dsh-sensitive-guard/hooks/pre-step
 */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-agent'
import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import { asBlocks, asContent, recordRedactions, sessionIdOf, type GuardRuntime } from './runtime.js'

export function registerPreStep(ctx: Context, runtime: GuardRuntime): void {
  const { config, redactor } = runtime
  if (!config.redact.userMessages) return

  ctx.on(
    'agent/pre-step',
    async (payload, next) => {
      const decision = await next()
      if (decision.kind !== 'enter') return decision

      const session = sessionIdOf(payload.agent)
      let changed = false
      const messages = decision.messages.map((message) => {
        const result = redactor.redactBlocks(asBlocks(message.content), config.levels.input)
        if (!result.changed) return message
        changed = true
        recordRedactions(runtime, 'pre-step', result.hits, { session })
        return { ...message, content: asContent<ContentBlock[]>(result.content) }
      })

      // Preserve every other field (notably startsRequestSeries) untouched.
      return changed ? { ...decision, messages } : decision
    },
    { prepend: true },
  )
}
