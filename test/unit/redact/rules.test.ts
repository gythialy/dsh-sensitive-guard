import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import type { Level } from '../../../src/contracts.js'
import { PII_CATEGORIES, SECRET_RULES } from '../../../src/redact/rules.js'
import {
  isHighEntropyToken,
  isRealApiKeyAssignment,
  isSecretEnvAssignment,
  isSensitiveKeyAssignment,
  luhnValid,
} from '../../../src/redact/filters.js'
import { resetSecretPlaceholderState } from '../../../src/redact/index.js'
import { BENIGN, SAMPLE } from '../../fixtures/redact/samples.js'
import { cleanupTempDirs, redactorFor, type ConfigOverrides } from './helpers.js'

afterEach(cleanupTempDirs)
beforeEach(() => resetSecretPlaceholderState())

function redact(level: Level, text: string, overrides: ConfigOverrides = {}) {
  return redactorFor(level, overrides).redactText(text, level)
}

describe('compiled rule table', () => {
  it('keeps every upstream rule global-flagged and ordered by tier', () => {
    expect(SECRET_RULES.length).toBeGreaterThanOrEqual(43)
    const tiers = SECRET_RULES.map((rule) => rule.tier)
    expect(tiers).toEqual([...tiers].sort((a, b) => a - b))
    for (const rule of SECRET_RULES) {
      expect(rule.pattern.global).toBe(true)
      expect(rule.category.length).toBeGreaterThan(0)
    }
  })

  it('marks exactly the PII categories as keyed pseudonym rules', () => {
    const flagged = SECRET_RULES.filter((rule) => rule.pii === true).map((rule) => rule.category)
    expect(new Set(flagged)).toEqual(PII_CATEGORIES)
    expect(flagged).toEqual(['email', 'phone-cn', 'phone-intl', 'id-cn', 'credit-card', 'ssn-us'])
  })

  it('reports the full table size as ruleCount', () => {
    const redactor = redactorFor('minimal')
    expect(redactor.ruleCount).toBe(SECRET_RULES.length)
  })
})

describe('tier 0 credentials', () => {
  it('redacts a multi-line PEM private key block', () => {
    const result = redact('minimal', SAMPLE.pem)
    expect(result.text).toMatch(/^\[SECRET:private-key:[A-Z2-7]{4}\]$/)
    expect(result.text).not.toContain('U3ludGhldGlj')
    expect(result.hits).toEqual([
      {
        category: 'private-key',
        count: 1,
        placeholderIds: [expect.stringMatching(/^[A-Z2-7]{4}$/)],
      },
    ])
  })

  it('redacts head- and tail-truncated PEM remnants', () => {
    const [begin = '', body = '', end = ''] = SAMPLE.pem.split('\n')

    const head = redact('minimal', `log line\n${end}\nafter`)
    expect(head.text).toContain('[SECRET:private-key-truncated:')
    expect(head.text).toContain('after')
    expect(head.text).not.toContain('PRIVATE KEY')
    expect(head.hits).toEqual([
      expect.objectContaining({ category: 'private-key-truncated', count: 1 }),
    ])

    const tail = redact('minimal', `${begin}\n${body}\n`)
    expect(tail.text).toMatch(/^\[SECRET:private-key-truncated:[A-Z2-7]{4}\]$/)
    expect(tail.text).not.toContain('U3ludGhldGlj')
  })

  it('redacts the leading truncation span and is idempotent afterwards', () => {
    const end = SAMPLE.pem.split('\n')[2] ?? ''
    const text = `a\n${end}\nb\n`
    const first = redact('minimal', text)
    expect(first.text).not.toContain('-----END')
    expect(first.text).toContain('b')
    expect(first.hits).toEqual([
      expect.objectContaining({ category: 'private-key-truncated', count: 1 }),
    ])

    const second = redact('minimal', first.text)
    expect(second.changed).toBe(false)
    expect(second.text).toBe(first.text)
  })

  it('redacts AWS, GitHub, and Google credentials', () => {
    for (const [value, category] of [
      [SAMPLE.awsAccessKey, 'aws-access-key'],
      [SAMPLE.githubToken, 'github-token'],
      [SAMPLE.googleApiKey, 'google-api-key'],
    ] as const) {
      const result = redact('minimal', `token=${value}`)
      expect(result.text).toContain(`[SECRET:${category}:`)
      expect(result.text).not.toContain(value)
    }
  })

  it('redacts OpenAI, Anthropic, and DeepSeek keys with distinct categories', () => {
    for (const [value, category] of [
      [SAMPLE.openaiKey, 'openai-key'],
      [SAMPLE.anthropicKey, 'anthropic-key'],
      [SAMPLE.deepseekKey, 'deepseek-key'],
    ] as const) {
      const result = redact('minimal', value)
      expect(result.text).toMatch(new RegExp(`^\\[SECRET:${category}:[A-Z2-7]{4}\\]$`))
    }
  })

  it('redacts bare JWTs and Bearer header values as generic-bearer', () => {
    const jwt = redact('minimal', `header ${SAMPLE.jwt} footer`)
    expect(jwt.text).toContain('[SECRET:generic-bearer:')
    expect(jwt.text).not.toContain(SAMPLE.jwt)
    const bearer = redact('minimal', `Authorization: ${SAMPLE.bearer}`)
    expect(bearer.text).toContain('[SECRET:generic-bearer:')
    expect(bearer.text).not.toContain(SAMPLE.bearer)
  })

  it('redacts URL userinfo credentials but keeps the host readable', () => {
    const result = redact('minimal', `db: ${SAMPLE.urlCredentials}`)
    expect(result.text).toMatch(
      /^db: \[SECRET:url-credentials:[A-Z2-7]{4}\]db\.synthetic\.test:5432\/app$/,
    )
  })

  it('redacts OAuth access_token query parameters', () => {
    const result = redact('minimal', SAMPLE.urlAccessToken)
    expect(result.text).toMatch(/callback\[SECRET:url-access-token:[A-Z2-7]{4}\]$/)
  })

  it('redacts slack, npm, gitlab, and telegram tokens', () => {
    for (const [value, category] of [
      [SAMPLE.slackToken, 'slack-token'],
      [SAMPLE.slackWebhook, 'slack-webhook-url'],
      [SAMPLE.npmToken, 'npm-token'],
      [SAMPLE.gitlabPat, 'gitlab-pat'],
      [SAMPLE.telegramToken, 'telegram-bot-token'],
    ] as const) {
      const result = redact('minimal', value)
      expect(result.text).toContain(`[SECRET:${category}:`)
    }
  })

  it('leaves near-miss credential shapes alone', () => {
    for (const nearMiss of [
      'AKIA1234',
      'ghp_short',
      'sk-abc',
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0',
      'postgres://db.synthetic.test/app',
      'Bearer short',
    ]) {
      const result = redact('minimal', nearMiss)
      expect(result.changed).toBe(false)
      expect(result.text).toBe(nearMiss)
    }
  })

  it('redacts generic api-key assignments and leaves documentation placeholders', () => {
    const real = redact('minimal', `api_key = "${SAMPLE.highEntropy}"`)
    expect(real.text).toContain('[SECRET:api-key:')
    expect(real.text).not.toContain(SAMPLE.highEntropy)

    const documentation = redact('minimal', SAMPLE.fakeApiKeyAssignment)
    expect(documentation.changed).toBe(false)
    expect(documentation.text).toBe(SAMPLE.fakeApiKeyAssignment)
  })
})

describe('tier 1 assignments', () => {
  it('redacts uppercase env assignments with a sensitive name segment', () => {
    const result = redact('balanced', SAMPLE.envSecret)
    expect(result.text).toContain('[SECRET:env-var-secret:')
    expect(result.text).not.toContain(SAMPLE.highEntropy)
  })

  it('redacts mixed/lowercase assignments with a sensitive name segment', () => {
    const result = redact('balanced', 'db_password=Q7mZ2vK9pR4tW1yB6nL3cD5f')
    expect(result.text).toContain('[SECRET:key-assignment:')
    expect(result.text).not.toContain(SAMPLE.highEntropy)
  })

  it('leaves safe env names, plain layout names, and code property chains alone', () => {
    for (const value of [
      SAMPLE.safeEnvName,
      SAMPLE.nonSensitiveEnvName,
      SAMPLE.propertyChainPassword,
      SAMPLE.propertyChainToken,
    ]) {
      const result = redact('balanced', value)
      expect(result.changed).toBe(false)
      expect(result.text).toBe(value)
    }
  })

  it('redacts tier 1 cloud credentials at balanced', () => {
    const result = redact('balanced', SAMPLE.alibabaAccessKey)
    expect(result.text).toContain('[SECRET:alibaba-access-key:')
    expect(result.text).not.toContain(SAMPLE.alibabaAccessKey)
  })

  it('does not run tier 1 rules at minimal', () => {
    expect(redact('minimal', SAMPLE.envSecret).changed).toBe(false)
    expect(redact('minimal', 'db_password=Q7mZ2vK9pR4tW1yB6nL3cD5f').changed).toBe(false)
  })
})

describe('tier 2 PII', () => {
  it('redacts an email as a keyed PII pseudonym', () => {
    const result = redact('aggressive', `mail ${SAMPLE.email} now`)
    expect(result.text).toMatch(/mail \[\[PII_EMAIL_[0-9a-f]{8}\]\] now/)
    expect(result.hits).toEqual([{ category: 'email', count: 1, pii: true }])
  })

  it('redacts a CN phone but not an ISO date', () => {
    const result = redact('aggressive', `call ${SAMPLE.phoneCn} on ${SAMPLE.isoDate}`)
    expect(result.text).toContain('[[PII_PHONE_CN_')
    expect(result.text).toContain(SAMPLE.isoDate)
    expect(result.hits.map((hit) => hit.category)).toEqual(['phone-cn'])
  })

  it('redacts an international phone number', () => {
    const result = redact('aggressive', `call ${SAMPLE.phoneIntl}`)
    expect(result.text).toContain('[[PII_PHONE_INTL_')
  })

  it('redacts a CN resident id before the credit-card fallback', () => {
    const result = redact('aggressive', `id ${SAMPLE.idCn}`)
    expect(result.text).toContain('[[PII_ID_CN_')
    expect(result.hits.map((hit) => hit.category)).toEqual(['id-cn'])
  })

  it('redacts a Luhn-valid card and keeps a Luhn-invalid number', () => {
    const valid = redact('aggressive', `card ${SAMPLE.cardValid}`)
    expect(valid.text).toContain('[[PII_CREDIT_CARD_')
    expect(valid.text).not.toContain(SAMPLE.cardValid)

    const invalid = redact('aggressive', `card ${SAMPLE.cardInvalid}`)
    expect(invalid.text).toBe(`card ${SAMPLE.cardInvalid}`)
    expect(invalid.changed).toBe(false)
  })

  it('redacts a US SSN', () => {
    const result = redact('aggressive', `ssn ${SAMPLE.ssnUs}`)
    expect(result.text).toContain('[[PII_SSN_US_')
  })
})

describe('tier 2 high-entropy fallback', () => {
  it('redacts a mixed-class token but keeps prose', () => {
    const token = redact('aggressive', `value ${SAMPLE.highEntropy}`)
    expect(token.text).toContain('[SECRET:high-entropy:')
    expect(token.text).not.toContain(SAMPLE.highEntropy)

    for (const prose of [SAMPLE.prose, SAMPLE.gluedProse, 'yourSyntheticTokenHere123456']) {
      const result = redact('aggressive', prose)
      expect(result.changed).toBe(false)
      expect(result.text).toBe(prose)
    }
  })

  it('does not run at minimal or balanced', () => {
    expect(redact('minimal', SAMPLE.highEntropy).changed).toBe(false)
    expect(redact('balanced', SAMPLE.highEntropy).changed).toBe(false)
  })
})

describe('benign text', () => {
  it('is untouched at every level', () => {
    for (const level of ['minimal', 'balanced', 'aggressive'] as const) {
      const result = redact(level, BENIGN)
      expect(result.changed).toBe(false)
      expect(result.text).toBe(BENIGN)
      expect(result.hits).toEqual([])
    }
  })
})

describe('vendored false-positive filters', () => {
  it('validates Luhn only for plausible card numbers', () => {
    expect(luhnValid('4111 1111 1111 1111')).toBe(true)
    expect(luhnValid('4111111111111112')).toBe(false)
  })

  it('requires a whole sensitive name segment for env assignments', () => {
    expect(isSecretEnvAssignment('AWS_SECRET_ACCESS_KEY=abc')).toBe(true)
    expect(isSecretEnvAssignment('MY_API_KEY=abc')).toBe(true)
    expect(isSecretEnvAssignment('PASSWORD_STORE_DIR=/tmp/pass')).toBe(false)
    expect(isSecretEnvAssignment('KEYBOARD_LAYOUT=us')).toBe(false)
    expect(isSecretEnvAssignment('MONKEY=banana')).toBe(false)
  })

  it('rejects dotted property chains and documentation values', () => {
    expect(isSensitiveKeyAssignment('password=req.body.password')).toBe(false)
    expect(isSensitiveKeyAssignment('token=response.data.token')).toBe(false)
    // The pattern stops at 'computeToken' (no parentheses in the value class),
    // so a short pure-letter identifier is rejected by the engine as well.
    expect(isSensitiveKeyAssignment('token=computeToken')).toBe(false)
    expect(redact('balanced', 'token=computeToken()').changed).toBe(false)
    expect(isSensitiveKeyAssignment('secret_key=Q7mZ2vK9pR4tW1yB6nL3cD5f')).toBe(true)
  })

  it('rejects documentation markers in api-key values', () => {
    expect(isRealApiKeyAssignment('api_key="your_api_key_here"')).toBe(false)
    expect(isRealApiKeyAssignment('api_key=Q7mZ2vK9pR4tW1yB6nL3cD5f')).toBe(true)
  })

  it('keeps prose out of the high-entropy fallback', () => {
    expect(isHighEntropyToken(SAMPLE.highEntropy)).toBe(true)
    expect(isHighEntropyToken(SAMPLE.prose)).toBe(false)
    expect(isHighEntropyToken(SAMPLE.gluedProse)).toBe(false)
    expect(isHighEntropyToken('yourSyntheticTokenHere123456')).toBe(false)
  })
})
