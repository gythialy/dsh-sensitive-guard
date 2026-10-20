import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AuditLog } from '../../src/audit.js'
import { runGuardCommand } from '../../src/commands/guard.js'
import { resolveConfig } from '../../src/config.js'
import type { GuardRuntime } from '../../src/hooks/runtime.js'
import type { PolicyEngine } from '../../src/contracts.js'
import { createRedactor } from '../../src/redact/index.js'
import { noopLogger } from '../../src/util/logger.js'

const dirs: string[] = []

async function makeRuntime(restore = true): Promise<{ runtime: GuardRuntime; dir: string }> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sg-command-'))
  dirs.push(dir)
  const config = resolveConfig({
    mode: 'monitor',
    pii: { enabled: true, restore, keyFile: path.join(dir, 'pii.key') },
    audit: { enabled: false },
  })
  const redactor = createRedactor({
    config,
    keyPath: path.join(dir, 'pii.key'),
    logger: noopLogger,
  })
  const policy: PolicyEngine = {
    evaluate: () => ({ action: 'allow', matched: false }),
    ruleCount: 7,
  }
  const audit = {
    decision: vi.fn(),
    redact: vi.fn(),
    error: vi.fn(),
    flush: vi.fn(async () => undefined),
    path: path.join(dir, 'audit.jsonl'),
  } as unknown as AuditLog
  return {
    dir,
    runtime: { config, redactor, policy, audit, logger: noopLogger, locale: () => 'en' },
  }
}

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

function placeholderFrom(text: string): string {
  const match = text.match(/\[\[PII_[A-Z0-9_]+_[0-9a-f]{8}\]\]/)
  if (!match) throw new Error('no placeholder in ' + text)
  return match[0]
}

describe('/guard command', () => {
  it('reports mode, rules, audit, and restore state', async () => {
    const { runtime } = await makeRuntime()
    const result = await runGuardCommand(runtime, ' status ')
    expect(result.kind).toBe('success')
    const text = result.kind === 'success' ? (result.text ?? '') : ''
    expect(text).toContain('mode: monitor')
    expect(text).toContain('rules: policy=7')
    expect(text).toContain('redaction=')
    expect(text).toContain('audit: off')
    expect(text).toContain('pii restore: on')
    expect(text).not.toContain('@')
  })

  it('renders status and mode text in Chinese when DSH is Chinese', async () => {
    const { runtime } = await makeRuntime()
    runtime.locale = () => 'zh'

    const status = await runGuardCommand(runtime, 'status')
    const text = status.kind === 'success' ? (status.text ?? '') : ''
    expect(text).toContain('敏感信息守卫')
    expect(text).toContain('模式: monitor')
    expect(text).toContain('规则: 策略=7')
    expect(text).toContain('PII 恢复: 开')

    const mode = await runGuardCommand(runtime, 'on')
    expect(mode.kind === 'success' ? mode.text : '').toContain('仅当前进程')
  })

  it('toggles the runtime mode without persisting it', async () => {
    const { runtime } = await makeRuntime()
    expect((await runGuardCommand(runtime, 'on')).kind).toBe('success')
    expect(runtime.config.mode).toBe('enforce')
    expect(runtime.audit.decision).toHaveBeenCalled()
    expect((await runGuardCommand(runtime, 'off')).kind).toBe('success')
    expect(runtime.config.mode).toBe('monitor')
  })

  it('rejects restore when the opt-in is off', async () => {
    const { runtime } = await makeRuntime(false)
    const result = await runGuardCommand(
      runtime,
      'restore [[PII_EMAIL_3f9a2c1d]] ' + path.join(os.tmpdir(), 'never'),
    )
    expect(result.kind).toBe('error')
    expect(result.kind === 'error' ? result.text : '').toContain('PII restore is off')
  })

  it('writes a restored PII value to a 0600 file without echoing it', async () => {
    const { runtime, dir } = await makeRuntime(true)
    const email = 'alice@example.com'
    const redacted = runtime.redactor.redactText(email, 'aggressive')
    const placeholder = placeholderFrom(redacted.text)
    const target = path.join(dir, 'restore.txt')

    const result = await runGuardCommand(runtime, `restore ${placeholder} ${target}`)
    expect(result.kind).toBe('success')
    const text = result.kind === 'success' ? (result.text ?? '') : ''
    expect(text).toContain(placeholder)
    expect(text).not.toContain(email)
    expect(await readFile(target, 'utf8')).toBe(email)
    expect((await stat(target)).mode & 0o777).toBe(0o600)
    expect(runtime.audit.decision).toHaveBeenCalled()
  })

  it('refuses to overwrite an existing target', async () => {
    const { runtime, dir } = await makeRuntime(true)
    const redacted = runtime.redactor.redactText('alice@example.com', 'aggressive')
    const placeholder = placeholderFrom(redacted.text)
    const target = path.join(dir, 'restore.txt')
    expect((await runGuardCommand(runtime, `restore ${placeholder} ${target}`)).kind).toBe(
      'success',
    )
    const second = await runGuardCommand(runtime, `restore ${placeholder} ${target}`)
    expect(second.kind).toBe('error')
    expect(second.kind === 'error' ? second.text : '').toContain('already exists')
  })

  it('rejects unknown placeholders and invalid grammar', async () => {
    const { runtime } = await makeRuntime(true)
    const unknown = await runGuardCommand(
      runtime,
      'restore [[PII_EMAIL_00000000]] ' + path.join(os.tmpdir(), 'x'),
    )
    expect(unknown.kind).toBe('error')
    const invalid = await runGuardCommand(runtime, 'restore not-a-placeholder /tmp/x')
    expect(invalid.kind).toBe('error')
    const usage = await runGuardCommand(runtime, 'restore')
    expect(usage.kind).toBe('error')
  })

  it('returns usage for unknown subcommands', async () => {
    const { runtime } = await makeRuntime()
    const result = await runGuardCommand(runtime, 'bogus')
    expect(result.kind).toBe('error')
    expect(result.kind === 'error' ? result.text : '').toContain('Usage:')
  })
})
