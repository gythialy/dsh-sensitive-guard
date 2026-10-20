import { describe, expect, it } from 'vitest'
import {
  approvalPrompt,
  approvalReason,
  cleanAction,
  cleanDetail,
  denyReason,
  formatBytes,
  guardUsage,
  modeText,
  noticeText,
  startupText,
  statusText,
  unknownCommandText,
} from '../../src/messages.js'

describe('guard messages', () => {
  it('builds an English approval prompt with tool, type, and action', () => {
    const prompt = approvalPrompt(
      'bash',
      {
        kind: 'high-risk-command',
        detail: 'Force-pushing rewrites remote history — confirm before proceeding',
      },
      { en: 'git push --force origin main', zh: 'git push --force origin main' },
    )

    expect(prompt.en).toContain('Sensitive Guard · Tool: bash')
    expect(prompt.en).toContain('Type: high-risk command')
    expect(prompt.en).toContain('Action: git push --force origin main')
    expect(prompt.en).toContain('Force-pushing rewrites remote history')
    expect(prompt.en).toContain('Approve once only if you expect this exact call')
    expect(prompt.en).not.toContain('AKIA')
  })

  it('builds the matching Chinese approval prompt', () => {
    const prompt = approvalPrompt(
      'bash',
      {
        kind: 'high-risk-command',
        detail: 'Force-pushing rewrites remote history — confirm before proceeding',
      },
      { en: 'git push --force origin main', zh: 'git push --force origin main' },
    )

    expect(prompt.zh).toContain('敏感信息守卫 · 工具：bash')
    expect(prompt.zh).toContain('类型：高风险命令')
    expect(prompt.zh).toContain('操作：git push --force origin main')
    expect(prompt.zh).toContain('命令命中了内置高风险规则')
    expect(prompt.zh).not.toContain('Force-pushing')
    expect(prompt.zh).toContain('仅确认本次调用符合预期时允许')
  })

  it('omits the action when no summary is available', () => {
    const prompt = approvalPrompt('read', { kind: 'sensitive-path' })
    expect(prompt.en).toContain(
      "Type: sensitive path. The path matches the guard's credential-path rules.",
    )
    expect(prompt.en).not.toContain('Action:')
    expect(prompt.zh).not.toContain('操作：')
  })

  it('states the risk and one next step for a denial in both languages', () => {
    const en = denyReason('bash', { kind: 'secret-in-arguments' })
    expect(en).toContain('Sensitive Guard blocked the bash call: credential in arguments.')
    expect(en).toContain('A credential pattern matched inside the tool arguments.')
    expect(en).toContain('Remove the credential or ask the user for a redacted value.')

    const zh = denyReason('bash', { kind: 'secret-in-arguments' }, 'zh')
    expect(zh).toContain('敏感信息守卫已阻止 bash 调用：参数中包含凭据。')
    expect(zh).toContain('工具参数中匹配到凭据模式。')
    expect(zh).toContain('请移除凭据，或向用户索取脱敏后的值。')

    const path = denyReason(
      'read',
      { kind: 'sensitive-path', detail: 'This path is denied by configuration' },
      'zh',
    )
    expect(path).toContain('路径命中了守卫的凭据路径规则。')
    expect(path).not.toContain('This path')
  })

  it('does not append a second instruction when the rule already gives one', () => {
    const en = denyReason('read', {
      kind: 'sensitive-path',
      detail:
        'This path is denied by configuration; ask the user or read a non-credential file instead',
    })
    expect(en).toContain('ask the user or read a non-credential file instead')
    expect(en).not.toContain('Ask the user for an allowed path')

    const zh = denyReason(
      'read',
      { kind: 'sensitive-path', detail: '该路径被配置拒绝；请询问用户或读取非凭据文件' },
      'zh',
    )
    expect(zh).not.toContain('请向用户索取允许的路径')
  })

  it('builds a model-facing approval reason in both languages', () => {
    expect(approvalReason('web_fetch', { kind: 'credential-query' })).toBe(
      'Sensitive Guard needs approval for the web_fetch call: credential-like URL query. A query parameter looks like a credential.',
    )
    expect(approvalReason('web_fetch', { kind: 'credential-query' }, 'zh')).toBe(
      '敏感信息守卫需要确认 web_fetch 调用：URL 查询参数包含疑似凭据。查询参数看起来像凭据。',
    )
  })

  it('normalizes rule reasons and actions', () => {
    expect(cleanDetail('sensitive-guard:  line one\nline two  ')).toBe('line one line two')
    expect(cleanDetail('原因。')).toBe('原因')
    expect(cleanDetail('   ')).toBeUndefined()
    expect(cleanDetail(undefined)).toBeUndefined()
    expect(cleanDetail('x'.repeat(300))?.length).toBeLessThanOrEqual(218)
    expect(cleanAction('  a\n b  ')).toBe('a b')
    expect(cleanAction('x'.repeat(300))?.length).toBeLessThanOrEqual(160)
  })

  it('prints a localized status block', () => {
    const status = {
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
    }
    const en = statusText(status)
    expect(en).toContain('Sensitive Guard')
    expect(en).toContain('  mode: enforce')
    expect(en).toContain('  fail closed: on')
    expect(en).toContain('  levels: input=aggressive, output=balanced')
    expect(en).toContain('  rules: policy=32, redaction=44')
    expect(en).toContain('  audit: on — /tmp/audit.jsonl')
    expect(en).toContain('  pii restore: on')

    const zh = statusText(status, 'zh')
    expect(zh).toContain('敏感信息守卫')
    expect(zh).toContain('  模式: enforce')
    expect(zh).toContain('  失败关闭: 开')
    expect(zh).toContain('  等级: 输入=aggressive，输出=balanced')
    expect(zh).toContain('  规则: 策略=32，脱敏=44')
    expect(zh).toContain('  PII 恢复: 开')
    expect(zh).toContain('  提示: /guard on|off 只影响当前进程')
  })

  it('prints a localized count-only redaction notice', () => {
    const hits = [
      { category: 'email', count: 2 },
      { category: 'aws-access-key', count: 1 },
    ]
    expect(noticeText(hits)).toBe(
      'Sensitive Guard redacted: email×2, aws-access-key×1. The originals were replaced with placeholders.',
    )
    expect(noticeText(hits, 'zh')).toBe(
      '敏感信息守卫已脱敏：email×2、aws-access-key×1。原值已替换为占位符。',
    )
  })

  it('prints localized usage and unknown-command help', () => {
    expect(guardUsage('en')).toContain('Usage: /guard <command>')
    expect(guardUsage('zh')).toContain('用法: /guard <command>')
    expect(guardUsage('en')).toContain('restore <placeholder> <file>')
    expect(unknownCommandText('bogus')).toContain('unknown command "bogus"')
    expect(unknownCommandText('帮助', 'zh')).toContain('未知命令 "帮助"')
  })

  it('describes runtime mode changes and startup state in both languages', () => {
    expect(modeText('enforce')).toContain('runtime only')
    expect(modeText('enforce', 'zh')).toContain('仅当前进程')

    const args = { mode: 'monitor', policyRules: 32, redactionRules: 44, auditEnabled: true }
    expect(startupText(args)).toBe(
      'Sensitive Guard active in monitor mode — 32 policy rules, 44 redaction rules, audit on.',
    )
    expect(startupText(args, 'zh')).toBe(
      '敏感信息守卫已启用：monitor 模式 — 32 条策略规则，44 条脱敏规则，审计已开启。',
    )
  })

  it('formats byte limits for people', () => {
    expect(formatBytes(128 * 1024)).toBe('128 KB')
    expect(formatBytes(1024 * 1024 * 1.5)).toBe('1.5 MB')
    expect(formatBytes(512)).toBe('512 B')
  })
})
