import { describe, expect, it } from 'vitest'
import {
  approvalPrompt,
  approvalReason,
  cleanDetail,
  denyReason,
  formatBytes,
  GUARD_USAGE,
  modeText,
  noticeText,
  startupText,
  statusText,
  unknownCommandText,
} from '../../src/messages.js'

describe('guard messages', () => {
  it('builds a localized approval prompt without argument values', () => {
    const prompt = approvalPrompt('bash', {
      kind: 'high-risk-command',
      detail: 'Force-pushing rewrites remote history — confirm before proceeding',
    })

    expect(prompt.en).toContain('Sensitive Guard · bash')
    expect(prompt.en).toContain('Risk: high-risk command')
    expect(prompt.en).toContain('Force-pushing rewrites remote history')
    expect(prompt.en).toContain('Approve once only if you expect this exact call')
    expect(prompt.en).not.toContain('AKIA')
    expect(prompt.zh).toContain('敏感信息守卫 · bash')
    expect(prompt.zh).toContain('风险：高风险命令')
    expect(prompt.zh).toContain('仅确认本次调用符合预期时允许')
  })

  it('falls back to a fixed explanation when a rule has no reason', () => {
    const prompt = approvalPrompt('read', { kind: 'sensitive-path' })
    expect(prompt.en).toContain(
      "Risk: sensitive path. The path matches the guard's credential-path rules.",
    )
  })

  it('states the risk and one next step for a denial', () => {
    const reason = denyReason('bash', { kind: 'secret-in-arguments' })
    expect(reason).toContain('Sensitive Guard blocked the bash call: credential in arguments.')
    expect(reason).toContain('A credential pattern matched inside the tool arguments.')
    expect(reason).toContain('Remove the credential or ask the user for a redacted value.')
  })

  it('does not append a second instruction when the rule already gives one', () => {
    const reason = denyReason('read', {
      kind: 'sensitive-path',
      detail:
        'This path is denied by configuration; ask the user or read a non-credential file instead',
    })
    expect(reason).toContain('ask the user or read a non-credential file instead')
    expect(reason).not.toContain('Ask the user for an allowed path')
  })

  it('builds a model-facing approval reason separately from the display prompt', () => {
    const reason = approvalReason('web_fetch', { kind: 'credential-query' })
    expect(reason).toBe(
      'Sensitive Guard needs approval for the web_fetch call: credential-like URL query. A query parameter looks like a credential.',
    )
  })

  it('normalizes rule reasons and strips module prefixes, control bytes, and excess length', () => {
    expect(cleanDetail('sensitive-guard:  line one\nline two  ')).toBe('line one line two')
    expect(cleanDetail('   ')).toBeUndefined()
    expect(cleanDetail(undefined)).toBeUndefined()
    expect(cleanDetail('x'.repeat(300))?.length).toBeLessThanOrEqual(218)
  })

  it('prints a labeled status block', () => {
    const text = statusText({
      mode: 'enforce',
      failClosed: true,
      inputLevel: 'aggressive',
      outputLevel: 'balanced',
      policyRules: 32,
      redactionRules: 44,
      auditEnabled: true,
      auditPath: '/tmp/audit.jsonl',
      piiEnabled: true,
      piiRestore: true,
    })

    expect(text).toContain('Sensitive Guard')
    expect(text).toContain('  mode: enforce')
    expect(text).toContain('  fail closed: on')
    expect(text).toContain('  levels: input=aggressive, output=balanced')
    expect(text).toContain('  rules: policy=32, redaction=44')
    expect(text).toContain('  audit: on — /tmp/audit.jsonl')
    expect(text).toContain('  pii restore: on')
    expect(text).toContain('  note: /guard on|off changes this process only')
  })

  it('prints a count-only redaction notice', () => {
    const text = noticeText([
      { category: 'email', count: 2 },
      { category: 'aws-access-key', count: 1 },
    ])
    expect(text).toBe(
      'Sensitive Guard redacted: email×2, aws-access-key×1. The originals were replaced with placeholders.',
    )
  })

  it('prints usage and unknown-command help', () => {
    expect(GUARD_USAGE).toContain('Usage: /guard <command>')
    expect(GUARD_USAGE).toContain('restore <placeholder> <file>')
    const text = unknownCommandText('bogus')
    expect(text).toContain('unknown command "bogus"')
    expect(text).toContain(GUARD_USAGE)
    expect(unknownCommandText('帮助')).toContain('unknown command "帮助"')
  })

  it('describes runtime mode changes and startup state', () => {
    expect(modeText('enforce')).toContain('runtime only')
    expect(
      startupText({ mode: 'monitor', policyRules: 32, redactionRules: 44, auditEnabled: true }),
    ).toBe(
      'Sensitive Guard active in monitor mode — 32 policy rules, 44 redaction rules, audit on.',
    )
  })

  it('formats byte limits for people', () => {
    expect(formatBytes(128 * 1024)).toBe('128 KB')
    expect(formatBytes(1024 * 1024 * 1.5)).toBe('1.5 MB')
    expect(formatBytes(512)).toBe('512 B')
  })
})
