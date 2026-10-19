import { describe, expect, it } from 'vitest'
import { inspectArguments } from '../../src/argguard/inspect.js'
import type {
  ContentRedaction,
  Level,
  Redactor,
  TextRedaction,
  ValueRedaction,
} from '../../src/contracts.js'

function fakeRedactor(needle: string): Redactor {
  const noText = (text: string): TextRedaction => ({ text, changed: false, hits: [] })
  const noValue = (value: ValueRedaction['value']): ValueRedaction => ({
    value,
    changed: false,
    hits: [],
  })
  const noContent: ContentRedaction = { content: [], changed: false, hits: [] }
  return {
    ruleCount: 1,
    scan: (text: string, _level: Level) => text.includes(needle),
    redactText: noText,
    redactValue: noValue,
    redactBlocks: () => noContent,
  }
}

describe('inspectArguments', () => {
  it('detects a tier-0 secret in nested arguments', () => {
    const result = inspectArguments(
      {
        command: 'curl -H "Authorization: Bearer sk-ant-example"',
        options: { nested: ['ok', 'sk-ant-example'] },
      },
      fakeRedactor('sk-ant-'),
      1024,
    )
    expect(result.hasSecret).toBe(true)
    expect(result.tooLarge).toBe(false)
  })

  it('ignores clean arguments', () => {
    const result = inspectArguments(
      { path: '/tmp/readme.md', lines: [1, 2, 3] },
      fakeRedactor('sk-ant-'),
      1024,
    )
    expect(result.hasSecret).toBe(false)
    expect(result.tooLarge).toBe(false)
  })

  it('reports oversized arguments without scanning them', () => {
    const result = inspectArguments({ blob: 'x'.repeat(2048) }, fakeRedactor('sk-ant-'), 128)
    expect(result.tooLarge).toBe(true)
    expect(result.bytes).toBeGreaterThan(128)
  })

  it('treats a circular structure as invalid rather than throwing', () => {
    const value: Record<string, unknown> = { name: 'loop' }
    value.self = value
    const result = inspectArguments(value, fakeRedactor('sk-ant-'), 1024)
    expect(result.tooLarge).toBe(true)
  })
})
