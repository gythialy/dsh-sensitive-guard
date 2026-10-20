/**
 * `agent/pre-step` arm: redact every admitted message before it is committed
 * as `user/message` and sent to the model. The original prompt remains in the
 * `agent/inbox/spliced` event, which the plugin cannot rewrite.
 * @module dsh-sensitive-guard/hooks/pre-step
 */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-agent'
import { createUserMessage, type ContentBlock } from '@deepseek-ai/dsh-llm'
import type { RedactionHit } from '../contracts.js'
import { noticeText } from '../messages.js'
import { asBlocks, asContent, recordRedactions, sessionIdOf, type GuardRuntime } from './runtime.js'

declare module '@deepseek-ai/dsh-llm' {
  interface MessageSourceMap {
    /** Plugin-authored user-role notices that are never treated as user input. */
    'sensitive-guard': {
      kind: 'sensitive-guard'
      form?: 'notice'
      summary?: string
    }
  }
}

function mergeHits(target: Map<string, number>, hits: readonly RedactionHit[]): void {
  for (const hit of hits) target.set(hit.category, (target.get(hit.category) ?? 0) + hit.count)
}

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
      const totals = new Map<string, number>()
      const messages = decision.messages.map((message) => {
        const result = redactor.redactBlocks(asBlocks(message.content), config.levels.input)
        if (!result.changed) return message
        changed = true
        mergeHits(totals, result.hits)
        recordRedactions(runtime, 'pre-step', result.hits, { session })
        return { ...message, content: asContent<ContentBlock[]>(result.content) }
      })

      if (!changed) return decision

      let nextMessages = messages
      if (config.redact.notify) {
        const hits = [...totals].map(([category, count]) => ({ category, count }))
        const text = noticeText(hits, runtime.locale())
        nextMessages = [
          ...messages,
          createUserMessage({
            content: [{ type: 'text', text }],
            source: {
              kind: 'sensitive-guard',
              form: 'notice',
              summary: text.slice(0, 120),
            },
          }),
        ]
      }

      // Preserve every other field (notably startsRequestSeries) untouched.
      return { ...decision, messages: nextMessages }
    },
    { prepend: true },
  )
}
