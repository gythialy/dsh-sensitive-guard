/**
 * `tools/post-execute` arm. On a hit the listener replaces the result without
 * delegating, so `dsh-spill-policy` never sees the plaintext. The `value`
 * channel is preferred because the tool renderer regenerates content from it
 * and PTC programs receive the redacted value as well.
 * @module dsh-sensitive-guard/hooks/post-execute
 */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-tools'
import type { ContentBlock, UserMessage } from '@deepseek-ai/dsh-llm'
import type { BlockLike, JsonValue, RedactionHit } from '../contracts.js'
import { asBlocks, asContent, recordRedactions, sessionIdOf, type GuardRuntime } from './runtime.js'

const WITHHELD = '[sensitive-guard] Redaction failed; the tool result was withheld.'

/** Redact one text block list, returning the original list when unchanged. */
function redactList(
  runtime: GuardRuntime,
  blocks: readonly BlockLike[],
  level: 'minimal' | 'balanced' | 'aggressive',
): { blocks: BlockLike[]; changed: boolean; hits: RedactionHit[] } {
  const result = runtime.redactor.redactBlocks(blocks, level)
  return result.changed
    ? { blocks: result.content, changed: true, hits: result.hits }
    : { blocks: [...blocks], changed: false, hits: [] }
}

function redactMessage(
  runtime: GuardRuntime,
  message: UserMessage,
  level: 'minimal' | 'balanced' | 'aggressive',
): { message: UserMessage; changed: boolean; hits: RedactionHit[] } {
  const result = redactList(runtime, asBlocks(message.content), level)
  if (!result.changed) return { message, changed: false, hits: [] }
  return {
    message: { ...message, content: asContent<ContentBlock[]>(result.blocks) },
    changed: true,
    hits: result.hits,
  }
}

export function registerPostExecute(ctx: Context, runtime: GuardRuntime): void {
  const { config, redactor, audit } = runtime
  if (!config.redact.toolResults) return

  ctx.on(
    'tools/post-execute',
    async (exec, result, next) => {
      const session = sessionIdOf(exec.agent)
      const level = config.levels.output
      try {
        // Scan both projections BEFORE delegating. A hit short-circuits the
        // waterfall so spill sees only redacted (or no) content.
        const contentRedaction = redactor.redactBlocks(asBlocks(result.content), level)
        const valueRedaction = result.isError
          ? undefined
          : redactor.redactValue(result.value as JsonValue, level)
        const valueChanged = valueRedaction?.changed === true
        const contentChanged = contentRedaction.changed

        if (valueChanged || contentChanged) {
          const hits = [...(valueRedaction?.hits ?? []), ...contentRedaction.hits]
          recordRedactions(runtime, 'post-execute', hits, {
            session,
            tool: exec.name,
            spillBypassed: true,
            ...(valueRedaction?.truncated || contentRedaction.truncated ? { truncated: true } : {}),
          })
          if (!result.isError && valueChanged && valueRedaction !== undefined) {
            return { kind: 'accept', value: valueRedaction.value }
          }
          return { kind: 'accept', content: asContent<ContentBlock[]>(contentRedaction.content) }
        }

        const decision = await next()

        if (decision.kind === 'accept' && decision.value !== undefined) {
          const redaction = redactor.redactValue(decision.value, level)
          if (!redaction.changed) return decision
          recordRedactions(runtime, 'post-execute', redaction.hits, { session, tool: exec.name })
          return { ...decision, value: redaction.value }
        }

        if (decision.kind === 'accept') {
          const content = decision.content ?? result.content
          const redacted = redactList(runtime, asBlocks(content), level)
          if (redacted.changed)
            recordRedactions(runtime, 'post-execute', redacted.hits, { session, tool: exec.name })
          const contexts = redactContexts(runtime, decision.additionalContexts, level)
          if (contexts.hits.length > 0) {
            recordRedactions(runtime, 'post-execute', contexts.hits, { session, tool: exec.name })
          }
          if (!redacted.changed && !contexts.changed) return decision
          return {
            ...decision,
            ...(redacted.changed ? { content: asContent<ContentBlock[]>(redacted.blocks) } : {}),
            ...(contexts.changed ? { additionalContexts: contexts.messages } : {}),
          }
        }

        // block: the corrective feedback is model-facing too.
        const feedback = redactList(runtime, asBlocks(decision.feedback), level)
        if (!feedback.changed) return decision
        recordRedactions(runtime, 'post-execute', feedback.hits, { session, tool: exec.name })
        return { ...decision, feedback: asContent<ContentBlock[]>(feedback.blocks) }
      } catch (error) {
        audit.error({
          tool: exec.name,
          ...(session === undefined ? {} : { session }),
          message: error instanceof Error ? error.name : 'redaction-error',
        })
        return { kind: 'block', feedback: [{ type: 'text', text: WITHHELD } as ContentBlock] }
      }
    },
    { prepend: true },
  )
}

function redactContexts(
  runtime: GuardRuntime,
  contexts: UserMessage[] | undefined,
  level: 'minimal' | 'balanced' | 'aggressive',
): { messages: UserMessage[]; changed: boolean; hits: RedactionHit[] } {
  if (!contexts || contexts.length === 0) return { messages: [], changed: false, hits: [] }
  let changed = false
  const hits: RedactionHit[] = []
  const messages = contexts.map((message) => {
    const result = redactMessage(runtime, message, level)
    if (!result.changed) return message
    changed = true
    hits.push(...result.hits)
    return result.message
  })
  return { messages, changed, hits }
}
