import { createHmac } from 'node:crypto'
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { resolveConfig } from '../../../src/config.js'
import { createPseudonymizer, createRedactor } from '../../../src/redact/index.js'
import { SAMPLE } from '../../fixtures/redact/samples.js'
import { captureLogger, cleanupTempDirs, configFor, keyPathInTempDir, tempDir } from './helpers.js'

afterEach(cleanupTempDirs)

describe('PII pseudonyms', () => {
  it('hashes TYPE:normalized-value with HMAC-SHA256 and 8 hex characters', () => {
    const key = Buffer.alloc(32, 9)
    const pseudonymizer = createPseudonymizer({ key })
    const expected = createHmac('sha256', key)
      .update(`EMAIL:${SAMPLE.email.toLowerCase()}`, 'utf8')
      .digest('hex')
      .slice(0, 8)
    expect(pseudonymizer.id('email', SAMPLE.email)).toBe(`[[PII_EMAIL_${expected}]]`)
  })

  it('normalizes per category so equivalent spellings share one id', () => {
    const pseudonymizer = createPseudonymizer({ key: Buffer.alloc(32, 3) })
    expect(pseudonymizer.id('email', SAMPLE.emailUpper)).toBe(
      pseudonymizer.id('email', SAMPLE.email),
    )
    expect(pseudonymizer.id('phone-cn', SAMPLE.phoneCnSpaced)).toBe(
      pseudonymizer.id('phone-cn', SAMPLE.phoneCn),
    )
    expect(pseudonymizer.id('credit-card', SAMPLE.cardValidSpaced)).toBe(
      pseudonymizer.id('credit-card', SAMPLE.cardValid),
    )
    expect(pseudonymizer.id('id-cn', SAMPLE.idCnLower)).toBe(pseudonymizer.id('id-cn', SAMPLE.idCn))
    expect(pseudonymizer.id('ssn-us', SAMPLE.ssnUsDigits)).toBe(
      pseudonymizer.id('ssn-us', SAMPLE.ssnUs),
    )
  })

  it('keeps the type in the HMAC domain, so equal digits differ across types', () => {
    const pseudonymizer = createPseudonymizer({ key: Buffer.alloc(32, 4) })
    expect(pseudonymizer.id('phone-cn', SAMPLE.phoneCn)).not.toBe(
      pseudonymizer.id('phone-intl', SAMPLE.phoneCn),
    )
  })

  it('formats non-alphanumeric categories as underscores', () => {
    const pseudonymizer = createPseudonymizer({ key: Buffer.alloc(32, 5) })
    expect(pseudonymizer.id('credit-card', SAMPLE.cardValid)).toMatch(
      /^\[\[PII_CREDIT_CARD_[0-9a-f]{8}\]\]$/,
    )
    expect(pseudonymizer.id('phone-intl', SAMPLE.phoneIntl)).toMatch(
      /^\[\[PII_PHONE_INTL_[0-9a-f]{8}\]\]$/,
    )
  })

  it('changes ids when the key rotates', () => {
    const first = createPseudonymizer({ key: Buffer.alloc(32, 1) })
    const second = createPseudonymizer({ key: Buffer.alloc(32, 2) })
    expect(first.id('email', SAMPLE.email)).not.toBe(second.id('email', SAMPLE.email))
  })
})

describe('PII key file', () => {
  it('creates a 32-byte key at mode 0600 under a 0700 parent', () => {
    const directory = path.join(tempDir(), 'nested')
    const keyPath = path.join(directory, 'sensitive-guard-pii.key')
    createPseudonymizer({ keyPath })
    expect(existsSync(keyPath)).toBe(true)
    expect(readFileSync(keyPath).length).toBe(32)
    expect(statSync(keyPath).mode & 0o777).toBe(0o600)
    expect(statSync(directory).mode & 0o777).toBe(0o700)
  })

  it('is stable across redactors that share one key file', () => {
    const keyPath = keyPathInTempDir()
    const config = configFor('aggressive')
    const first = createRedactor({ config, keyPath }).redactText(SAMPLE.email, 'aggressive')
    const second = createRedactor({ config, keyPath }).redactText(SAMPLE.email, 'aggressive')
    expect(first.text).toBe(second.text)
    expect(first.text).toMatch(/^\[\[PII_EMAIL_[0-9a-f]{8}\]\]$/)
  })

  it('defaults to $DSH_HOME/sensitive-guard-pii.key', () => {
    const home = tempDir()
    const redactor = createRedactor({
      config: configFor('aggressive'),
      env: { DSH_HOME: home },
      home,
    })
    redactor.redactText(SAMPLE.email, 'aggressive')
    expect(existsSync(path.join(home, 'sensitive-guard-pii.key'))).toBe(true)
  })

  it('does not create a key file when PII is disabled', () => {
    const keyPath = keyPathInTempDir()
    const redactor = createRedactor({
      config: configFor('aggressive', { piiEnabled: false }),
      keyPath,
    })
    redactor.redactText(SAMPLE.email, 'aggressive')
    expect(existsSync(keyPath)).toBe(false)
  })

  it('honors config.pii.keyFile', () => {
    const keyPath = path.join(tempDir(), 'config-key.pii')
    const config = resolveConfig({
      levels: { input: 'aggressive', output: 'aggressive' },
      pii: { enabled: true, keyFile: keyPath },
    })
    createRedactor({ config }).redactText(SAMPLE.email, 'aggressive')
    expect(existsSync(keyPath)).toBe(true)
  })

  it('falls back to one process-random key when the key file is unreadable', () => {
    const directory = tempDir()
    const { logger, warnings } = captureLogger()
    const first = createPseudonymizer({ keyPath: directory, logger })
    const second = createPseudonymizer({ keyPath: directory, logger })
    expect(first.id('email', SAMPLE.email)).toBe(second.id('email', SAMPLE.email))
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain('ephemeral process key')
  })

  it('falls back when the key file has an invalid length', () => {
    const keyPath = path.join(tempDir(), 'short.key')
    writeFileSync(keyPath, Buffer.alloc(16, 7))
    const { logger } = captureLogger()
    const pseudonymizer = createPseudonymizer({ keyPath, logger })
    expect(pseudonymizer.id('email', SAMPLE.email)).toMatch(/^\[\[PII_EMAIL_[0-9a-f]{8}\]\]$/)
    expect(readFileSync(keyPath).length).toBe(16)
  })

  it('prefers an explicit key over a key path', () => {
    const key = Buffer.alloc(32, 6)
    const pseudonymizer = createPseudonymizer({ key, keyPath: tempDir() })
    const expected = createHmac('sha256', key)
      .update(`EMAIL:${SAMPLE.email}`, 'utf8')
      .digest('hex')
      .slice(0, 8)
    expect(pseudonymizer.id('email', SAMPLE.email)).toBe(`[[PII_EMAIL_${expected}]]`)
  })
})
