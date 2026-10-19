import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import type { BlockLike, JsonValue } from '../../../src/contracts.js'
import { resetSecretPlaceholderState } from '../../../src/redact/index.js'
import { SAMPLE } from '../../fixtures/redact/samples.js'
import { cleanupTempDirs, redactorFor, type ConfigOverrides } from './helpers.js'

afterEach(cleanupTempDirs)
beforeEach(() => resetSecretPlaceholderState())

function redactorAt(level: 'minimal' | 'balanced' | 'aggressive', overrides: ConfigOverrides = {}) {
  return redactorFor(level, overrides)
}

describe('scan', () => {
  it('detects rules according to the level', () => {
    const redactor = redactorAt('aggressive')
    expect(redactor.scan(SAMPLE.awsAccessKey, 'minimal')).toBe(true)
    expect(redactor.scan(SAMPLE.email, 'minimal')).toBe(false)
    expect(redactor.scan(SAMPLE.email, 'balanced')).toBe(false)
    expect(redactor.scan(SAMPLE.email, 'aggressive')).toBe(true)
    expect(redactor.scan('plain deploy notes', 'aggressive')).toBe(false)
  })

  it('ignores existing placeholders', () => {
    const redactor = redactorAt('aggressive')
    const first = redactor.redactText(`${SAMPLE.awsAccessKey} ${SAMPLE.email}`, 'aggressive')
    expect(first.changed).toBe(true)
    expect(redactor.scan(first.text, 'aggressive')).toBe(false)
  })
})

describe('redactText', () => {
  it('is idempotent', () => {
    const redactor = redactorAt('aggressive')
    const first = redactor.redactText(
      `${SAMPLE.pem}\n${SAMPLE.awsAccessKey} ${SAMPLE.email} ${SAMPLE.highEntropy}`,
      'aggressive',
    )
    expect(first.changed).toBe(true)
    const second = redactor.redactText(first.text, 'aggressive')
    expect(second.changed).toBe(false)
    expect(second.text).toBe(first.text)
    expect(second.hits).toEqual([])
  })

  it('aggregates repeated hits by category', () => {
    const redactor = redactorAt('minimal')
    const other = 'AKIA' + 'QWERTYUIOPASDFGH'
    const result = redactor.redactText(
      `${SAMPLE.awsAccessKey} ${SAMPLE.awsAccessKey} ${other}`,
      'minimal',
    )
    expect(result.hits).toHaveLength(1)
    expect(result.hits[0]!.category).toBe('aws-access-key')
    expect(result.hits[0]!.count).toBe(3)
    expect(result.hits[0]!.placeholderIds).toHaveLength(2)
  })

  it('never exposes original values in hits', () => {
    const result = redactorAt('minimal').redactText(SAMPLE.awsAccessKey, 'minimal')
    const serialized = JSON.stringify(result.hits)
    expect(serialized).not.toContain(SAMPLE.awsAccessKey)
    for (const id of result.hits[0]!.placeholderIds ?? []) {
      expect(id).toMatch(/^[A-Z2-7]{4}$/)
    }
  })
})

describe('redactValue', () => {
  it('returns the same reference when nothing changes', () => {
    const input: JsonValue = {
      number: 42,
      boolean: true,
      nothing: null,
      text: 'plain deploy notes',
      list: [1, 'plain', false],
      nested: { note: 'still plain' },
    }
    const result = redactorAt('aggressive').redactValue(input, 'aggressive')
    expect(result.changed).toBe(false)
    expect(result.value).toBe(input)
    expect(result.hits).toEqual([])
  })

  it('rewrites strings and preserves structure, values, and untouched references', () => {
    const input: JsonValue = {
      keep: { nested: 'plain' },
      secret: SAMPLE.email,
      count: 3,
      flag: true,
      nothing: null,
      list: ['ok', SAMPLE.awsAccessKey],
    }
    const result = redactorAt('aggressive').redactValue(input, 'aggressive')
    expect(result.changed).toBe(true)
    expect(result.value).not.toBe(input)

    const output = result.value as { [key: string]: JsonValue }
    expect(output.keep).toBe((input as { [key: string]: JsonValue }).keep)
    expect(output.count).toBe(3)
    expect(output.flag).toBe(true)
    expect(output.nothing).toBeNull()
    expect(output.secret).toMatch(/^\[\[PII_EMAIL_[0-9a-f]{8}\]\]$/)

    const list = output.list as JsonValue[]
    expect(list[0]).toBe('ok')
    expect(list[1]).toMatch(/^\[SECRET:aws-access-key:[A-Z2-7]{4}\]$/)

    const categories = result.hits.map((hit) => hit.category)
    expect(categories).toEqual(['email', 'aws-access-key'])
  })

  it('rebuilds objects without prototype pollution through a __proto__ key', () => {
    const input = JSON.parse(
      '{"__proto__":{"polluted":true},"secret":"' + SAMPLE.email + '"}',
    ) as JsonValue
    const result = redactorAt('aggressive').redactValue(input, 'aggressive')
    expect(result.changed).toBe(true)
    const output = result.value as { [key: string]: JsonValue }
    expect(Object.getPrototypeOf(output)).toBe(Object.prototype)
    expect(Object.prototype.hasOwnProperty.call(output, '__proto__')).toBe(true)
    expect(Object.prototype).not.toHaveProperty('polluted')
  })

  it('is idempotent for values', () => {
    const redactor = redactorAt('aggressive')
    const input: JsonValue = { a: SAMPLE.email, b: [SAMPLE.awsAccessKey] }
    const first = redactor.redactValue(input, 'aggressive')
    const second = redactor.redactValue(first.value, 'aggressive')
    expect(second.changed).toBe(false)
    expect(second.value).toBe(first.value)
  })
})

describe('redactBlocks', () => {
  it('returns the original array when no text block changes', () => {
    const blocks: BlockLike[] = [
      { type: 'text', text: 'plain deploy notes' },
      { type: 'text' },
      { type: 'image', data: 'opaque' },
    ]
    const result = redactorAt('aggressive').redactBlocks(blocks, 'aggressive')
    expect(result.changed).toBe(false)
    expect(result.content).toBe(blocks)
    expect(result.content[0]).toBe(blocks[0])
    expect(result.content[2]).toBe(blocks[2])
  })

  it('rewrites only changed text blocks and keeps other blocks by reference', () => {
    const blocks: BlockLike[] = [
      { type: 'text', text: `mail ${SAMPLE.email}`, extra: 'kept' },
      { type: 'image', data: 'opaque' },
      { type: 'text', text: 'plain deploy notes' },
    ]
    const result = redactorAt('aggressive').redactBlocks(blocks, 'aggressive')
    expect(result.changed).toBe(true)
    expect(result.content).not.toBe(blocks)
    expect(result.content[0]).not.toBe(blocks[0])
    expect(result.content[0]!.text).toContain('[[PII_EMAIL_')
    expect(result.content[0]!.extra).toBe('kept')
    expect(result.content[1]).toBe(blocks[1])
    expect(result.content[2]).toBe(blocks[2])
    expect(result.hits).toEqual([{ category: 'email', count: 1, pii: true }])
  })
})

describe('limits.maxScanBytes', () => {
  it('scans oversized input in chunks and flags chunking', () => {
    const redactor = redactorAt('aggressive', { maxScanBytes: 200 })
    const text = `head ${SAMPLE.awsAccessKey} ${'a'.repeat(1000)} tail ${SAMPLE.githubToken}`
    const result = redactor.redactText(text, 'aggressive')
    expect(result.truncated).toBe(true)
    expect(result.changed).toBe(true)
    expect(result.text).toContain('[SECRET:aws-access-key:')
    expect(result.text).toContain('[SECRET:github-token:')
    expect(result.text).not.toContain(SAMPLE.awsAccessKey)
    expect(result.text).not.toContain(SAMPLE.githubToken)
    expect(result.text).toContain('a'.repeat(100))
  })

  it('finds a secret in the middle of oversized input', () => {
    const redactor = redactorAt('minimal', { maxScanBytes: 200 })
    const text = `${'a'.repeat(500)} ${SAMPLE.awsAccessKey} ${'a'.repeat(500)}`
    const result = redactor.redactText(text, 'minimal')
    expect(result.truncated).toBe(true)
    expect(result.changed).toBe(true)
    expect(result.text).toContain('[SECRET:aws-access-key:')
    expect(result.text).not.toContain(SAMPLE.awsAccessKey)
  })

  it('is idempotent for oversized input', () => {
    const redactor = redactorAt('aggressive', { maxScanBytes: 200 })
    const text = `head ${SAMPLE.awsAccessKey} ${'a'.repeat(1000)} tail ${SAMPLE.githubToken}`
    const first = redactor.redactText(text, 'aggressive')
    const second = redactor.redactText(first.text, 'aggressive')
    expect(second.changed).toBe(false)
    expect(second.text).toBe(first.text)
    expect(second.truncated).toBe(true)
  })

  it('never throws on huge input', () => {
    const redactor = redactorAt('aggressive', { maxScanBytes: 1024 })
    const huge = 'x'.repeat(250_000)
    const result = redactor.redactText(huge, 'aggressive')
    expect(result.changed).toBe(false)
    expect(result.truncated).toBe(true)
    expect(redactor.scan(huge, 'aggressive')).toBe(false)
  })
})
