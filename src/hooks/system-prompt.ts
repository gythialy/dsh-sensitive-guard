/**
 * `system-prompt/assemble` arm: rewrite section text, runtime-context text, and
 * string variables after every other provider has assembled them. Tool schemas
 * are deliberately untouched.
 * @module dsh-sensitive-guard/hooks/system-prompt
 */
import type { Context } from '@deepseek-ai/cordis'
import type { PromptAssembly } from '@deepseek-ai/dsh-system-prompt'
import type {} from '@deepseek-ai/dsh-agent'
import type { RedactionHit } from '../contracts.js'
import { recordRedactions, type GuardRuntime } from './runtime.js'

const WITHHELD_SECTION = '[sensitive-guard] System prompt withheld after a redaction failure.'

export function registerSystemPrompt(ctx: Context, runtime: GuardRuntime): void {
  const { config, redactor, audit } = runtime
  if (!config.redact.systemPrompt) return

  ctx.on(
    'system-prompt/assemble',
    async (_assembly, _context, next) => {
      const assembly = await next()
      try {
        const level = config.levels.output
        const hits: RedactionHit[] = []
        let changed = false

        const sections = assembly.sections.map((section) => {
          const result = redactor.redactText(section.text, level)
          if (!result.changed) return section
          changed = true
          hits.push(...result.hits)
          return { ...section, text: result.text }
        })

        const contexts = assembly.contexts.map((context) => {
          const result = redactor.redactText(context.text, level)
          if (!result.changed) return context
          changed = true
          hits.push(...result.hits)
          return { ...context, text: result.text }
        })

        let variables = assembly.variables
        const entries = Object.entries(variables)
        let variablesChanged = false
        const nextVariables: Record<string, string | undefined> = {}
        for (const [name, value] of entries) {
          if (typeof value !== 'string') {
            nextVariables[name] = value
            continue
          }
          const result = redactor.redactText(value, level)
          if (result.changed) {
            variablesChanged = true
            hits.push(...result.hits)
          }
          nextVariables[name] = result.text
        }
        if (variablesChanged) {
          changed = true
          variables = nextVariables
        }

        if (!changed) return assembly
        recordRedactions(runtime, 'system-prompt', hits, {})
        return { ...assembly, sections, contexts, variables }
      } catch (error) {
        audit.error({ message: error instanceof Error ? error.name : 'redaction-error' })
        const fallback: PromptAssembly = {
          sections: [{ name: 'sensitive-guard', text: WITHHELD_SECTION, interpolate: false }],
          contexts: [],
          tools: assembly.tools,
          variables: {},
        }
        return fallback
      }
    },
    { prepend: true },
  )
}
