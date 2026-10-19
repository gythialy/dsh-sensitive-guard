import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { resetSecretPlaceholderState } from '../../../src/redact/index.js'
import { SAMPLE } from '../../fixtures/redact/samples.js'
import { cleanupTempDirs, redactorFor } from './helpers.js'

afterEach(cleanupTempDirs)
beforeEach(() => resetSecretPlaceholderState())

function secretId(text: string, category: string): string {
  const match = new RegExp(`\\[SECRET:${category}:([A-Z2-7]{4})\\]`).exec(text)
  expect(match, `missing ${category} placeholder in ${text}`).not.toBeNull()
  return match![1]!
}

describe('secret placeholders', () => {
  it('uses the [SECRET:<category>:<base32 id>] shape', () => {
    const result = redactorFor('minimal').redactText(SAMPLE.awsAccessKey, 'minimal')
    expect(result.text).toMatch(/^\[SECRET:aws-access-key:[A-Z2-7]{4}\]$/)
  })

  it('reuses one id for the same original value across calls', () => {
    const redactor = redactorFor('minimal')
    const first = redactor.redactText(`first ${SAMPLE.awsAccessKey}`, 'minimal')
    const second = redactor.redactText(`second ${SAMPLE.awsAccessKey}`, 'minimal')
    expect(secretId(first.text, 'aws-access-key')).toBe(secretId(second.text, 'aws-access-key'))
  })

  it('reuses one id across independent redactors in the same process', () => {
    const first = redactorFor('minimal').redactText(SAMPLE.awsAccessKey, 'minimal')
    const second = redactorFor('minimal').redactText(SAMPLE.awsAccessKey, 'minimal')
    expect(secretId(first.text, 'aws-access-key')).toBe(secretId(second.text, 'aws-access-key'))
  })

  it('mints distinct ids for distinct original values', () => {
    const other = 'AKIA' + 'QWERTYUIOPASDFGH'
    const redactor = redactorFor('minimal')
    const result = redactor.redactText(`${SAMPLE.awsAccessKey} ${other}`, 'minimal')
    const ids = [...result.text.matchAll(/\[SECRET:aws-access-key:([A-Z2-7]{4})\]/g)].map(
      (match) => match[1]!,
    )
    expect(ids).toHaveLength(2)
    expect(new Set(ids).size).toBe(2)
  })

  it('reports the minted ids in hits without leaking the original value', () => {
    const result = redactorFor('minimal').redactText(
      `${SAMPLE.awsAccessKey} ${SAMPLE.awsAccessKey}`,
      'minimal',
    )
    expect(result.hits).toHaveLength(1)
    const [hit] = result.hits
    expect(hit!.category).toBe('aws-access-key')
    expect(hit!.count).toBe(2)
    expect(hit!.placeholderIds).toEqual([secretId(result.text, 'aws-access-key')])
    expect(JSON.stringify(result.hits)).not.toContain(SAMPLE.awsAccessKey)
  })

  it('keeps the placeholder stable for process-wide reuse after a reset', () => {
    const first = redactorFor('minimal').redactText(SAMPLE.awsAccessKey, 'minimal')
    expect(first.text).toMatch(/^\[SECRET:aws-access-key:[A-Z2-7]{4}\]$/)
    resetSecretPlaceholderState()
    const second = redactorFor('minimal').redactText(SAMPLE.awsAccessKey, 'minimal')
    expect(second.text).toMatch(/^\[SECRET:aws-access-key:[A-Z2-7]{4}\]$/)
  })
})
