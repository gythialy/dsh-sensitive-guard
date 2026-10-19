import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { resetSecretPlaceholderState } from '../../../src/redact/index.js'
import { SAMPLE } from '../../fixtures/redact/samples.js'
import { cleanupTempDirs, redactorFor } from './helpers.js'

afterEach(cleanupTempDirs)
beforeEach(() => resetSecretPlaceholderState())

describe('level tiers', () => {
  it('minimal runs tier 0 only', () => {
    expect(redactorFor('minimal').redactText(SAMPLE.awsAccessKey, 'minimal').changed).toBe(true)
    expect(redactorFor('minimal').redactText(SAMPLE.envSecret, 'minimal').changed).toBe(false)
    expect(redactorFor('minimal').redactText(SAMPLE.email, 'minimal').changed).toBe(false)
    expect(redactorFor('minimal').redactText(SAMPLE.highEntropy, 'minimal').changed).toBe(false)
  })

  it('balanced adds tier 1 assignments', () => {
    expect(redactorFor('balanced').redactText(SAMPLE.envSecret, 'balanced').changed).toBe(true)
    expect(
      redactorFor('balanced').redactText('db_password=Q7mZ2vK9pR4tW1yB6nL3cD5f', 'balanced')
        .changed,
    ).toBe(true)
    expect(redactorFor('balanced').redactText(SAMPLE.email, 'balanced').changed).toBe(false)
    expect(redactorFor('balanced').redactText(SAMPLE.highEntropy, 'balanced').changed).toBe(false)
  })

  it('aggressive adds tier 2 PII and the entropy fallback', () => {
    const redactor = redactorFor('aggressive')
    expect(redactor.redactText(SAMPLE.email, 'aggressive').changed).toBe(true)
    expect(redactor.redactText(SAMPLE.phoneCn, 'aggressive').changed).toBe(true)
    expect(redactor.redactText(SAMPLE.idCn, 'aggressive').changed).toBe(true)
    expect(redactor.redactText(SAMPLE.cardValid, 'aggressive').changed).toBe(true)
    expect(redactor.redactText(SAMPLE.ssnUs, 'aggressive').changed).toBe(true)
    expect(redactor.redactText(SAMPLE.highEntropy, 'aggressive').changed).toBe(true)
  })
})

describe('pii.enabled gate', () => {
  it('disables every PII category while keeping the entropy fallback', () => {
    const redactor = redactorFor('aggressive', { piiEnabled: false })
    for (const value of [
      SAMPLE.email,
      SAMPLE.phoneCn,
      SAMPLE.phoneIntl,
      SAMPLE.idCn,
      SAMPLE.cardValid,
      SAMPLE.ssnUs,
    ]) {
      const result = redactor.redactText(value, 'aggressive')
      expect(result.changed).toBe(false)
      expect(result.text).toBe(value)
    }
    const entropy = redactor.redactText(SAMPLE.highEntropy, 'aggressive')
    expect(entropy.changed).toBe(true)
    expect(entropy.text).toContain('[SECRET:high-entropy:')
  })

  it('does not activate PII at minimal or balanced even when enabled', () => {
    for (const level of ['minimal', 'balanced'] as const) {
      const result = redactorFor(level, { piiEnabled: true }).redactText(SAMPLE.email, level)
      expect(result.changed).toBe(false)
    }
  })

  it('uses keyed PII pseudonyms, not secret placeholders', () => {
    const redactor = redactorFor('aggressive')
    for (const [value, label] of [
      [SAMPLE.email, 'EMAIL'],
      [SAMPLE.phoneCn, 'PHONE_CN'],
      [SAMPLE.phoneIntl, 'PHONE_INTL'],
      [SAMPLE.idCn, 'ID_CN'],
      [SAMPLE.cardValid, 'CREDIT_CARD'],
      [SAMPLE.ssnUs, 'SSN_US'],
    ] as const) {
      const result = redactor.redactText(value, 'aggressive')
      expect(result.text).toMatch(new RegExp(`^\\[\\[PII_${label}_[0-9a-f]{8}\\]\\]$`))
      expect(result.hits[0]?.pii).toBe(true)
    }
  })
})
