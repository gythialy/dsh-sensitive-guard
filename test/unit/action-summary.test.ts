import { describe, expect, it } from 'vitest'
import { summarizeAction } from '../../src/action-summary.js'
import { resolveConfig } from '../../src/config.js'
import { createRedactor } from '../../src/redact/index.js'
import { noopLogger } from '../../src/util/logger.js'

const AWS_KEY = 'AKIA' + '1234567890' + 'ABCDEF'
const redactor = createRedactor({
  config: resolveConfig({ pii: { enabled: false }, audit: { enabled: false } }),
  logger: noopLogger,
})

describe('approval action summaries', () => {
  it('shows a shell command as the action', () => {
    expect(summarizeAction('bash', { command: 'git push --force origin main' }, redactor)).toEqual({
      en: 'git push --force origin main',
      zh: 'git push --force origin main',
    })
  })

  it('redacts credentials from the action', () => {
    const action = summarizeAction('bash', { command: 'echo ' + AWS_KEY }, redactor)
    expect(action?.en).toContain('[SECRET:aws-access-key:')
    expect(action?.en).not.toContain(AWS_KEY)
  })

  it('removes URL credentials and masks query values', () => {
    const action = summarizeAction(
      'web_fetch',
      { url: 'https://alice:s3cret@example.test/x?token=s3cret&q=1' },
      redactor,
    )
    expect(action?.en).toBe('fetch https://example.test/x?token=***&q=***')
    expect(action?.zh).toBe('请求 https://example.test/x?token=***&q=***')
    expect(action?.en).not.toContain('alice')
    expect(action?.en).not.toContain('s3cret')
  })

  it('shows a path for file tools and compact JSON for other tools', () => {
    expect(summarizeAction('read', { file_path: '.env' }, redactor)).toEqual({
      en: 'read .env',
      zh: '读取 .env',
    })
    expect(summarizeAction('mcp__custom', { query: 'bar' }, redactor)?.en).toBe(
      'call {"query":"bar"}',
    )
  })

  it('returns undefined for empty arguments and truncates long actions', () => {
    expect(summarizeAction('read', null, redactor)).toBeUndefined()
    const action = summarizeAction('bash', { command: 'x'.repeat(400) }, redactor)
    expect(action?.en.length).toBeLessThanOrEqual(160)
  })
})
