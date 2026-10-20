import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AuditLog } from '../../src/audit.js'
import { runGuardCommand } from '../../src/commands/guard.js'
import { resolveConfig } from '../../src/config.js'
import type { EgressController, EgressSnapshot } from '../../src/egress/index.js'
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

describe('/guard egress', () => {
  const snapshot: EgressSnapshot = {
    enabled: true,
    bound: true,
    host: '127.0.0.1',
    port: 41_999,
    mode: 'monitor',
    unknown: 'allow',
    failClosed: true,
    allowRules: 0,
    denyRules: 1,
    proxyEnv: 'http://127.0.0.1:41999',
    envMatches: true,
    counts: { tunnels: 2, allowed: 2, denied: 0, bytesIn: 2048, bytesOut: 1024 },
    lastCanary: { ok: true, code: 'ok', latencyMs: 3, status: 200 },
    recent: [
      {
        host: 'api.example.com',
        port: 443,
        decision: 'allow',
        enforced: false,
        reason: 'unknown-allow',
      },
    ],
  }

  function controller(overrides: Partial<EgressController> = {}): EgressController {
    return {
      port: snapshot.port,
      bound: true,
      snapshot: () => snapshot,
      canary: async () => ({ ok: true, code: 'ok', latencyMs: 3, status: 200 }),
      close: async () => undefined,
      ...overrides,
    }
  }

  async function egressRuntime(controllerValue?: EgressController): Promise<GuardRuntime> {
    const { runtime } = await makeRuntime()
    runtime.config.egress.enabled = true
    if (controllerValue !== undefined) runtime.egress = controllerValue
    return runtime
  }

  it('explains that the guard is off before it is configured', async () => {
    const { runtime } = await makeRuntime()
    const result = await runGuardCommand(runtime, 'egress')
    expect(result.kind).toBe('error')
    expect(result.kind === 'error' ? result.text : '').toContain('egress guard is off')
  })

  it('reports a configured-but-unmounted guard', async () => {
    const runtime = await egressRuntime()
    const result = await runGuardCommand(runtime, 'egress')
    expect(result.kind).toBe('error')
    expect(result.kind === 'error' ? result.text : '').toContain('mounted no listener')
  })

  it('renders listener, wiring, rules, traffic, and recents', async () => {
    const runtime = await egressRuntime(controller())
    const result = await runGuardCommand(runtime, 'egress status')
    expect(result.kind).toBe('success')
    const text = result.kind === 'success' ? (result.text ?? '') : ''
    expect(text).toContain('listener: 127.0.0.1:41999')
    expect(text).toContain('bound')
    expect(text).toContain('https_proxy points at this listener')
    expect(text).toContain('deny=1, allow=0, unknown=allow')
    expect(text).toContain('tunnels=2')
    expect(text).toContain('api.example.com:443 allow(unknown-allow)')
    expect(text).toContain('canary: ok')
    expect(text).not.toContain('secret')
  })

  it('reports the canary result, success and failure', async () => {
    const runtime = await egressRuntime(controller())
    const ok = await runGuardCommand(runtime, 'egress canary')
    expect(ok.kind).toBe('success')
    expect(ok.kind === 'success' ? ok.text : '').toContain('canary: ok')

    const failing = controller({
      canary: async () => ({ ok: false, code: 'refused', latencyMs: 1 }),
    })
    const failed = await runGuardCommand(await egressRuntime(failing), 'egress canary')
    expect(failed.kind).toBe('error')
    const text = failed.kind === 'error' ? failed.text : ''
    expect(text).toContain('connection refused')
    expect(text).toContain('https_proxy=http://127.0.0.1:41999')
  })

  it('shows a count-only egress line in /guard status', async () => {
    const runtime = await egressRuntime(controller())
    const result = await runGuardCommand(runtime, 'status')
    const text = result.kind === 'success' ? (result.text ?? '') : ''
    expect(text).toContain('egress: 127.0.0.1:41999 bound (monitor), env ok')
  })

  it('localizes the egress surfaces', async () => {
    const runtime = await egressRuntime(controller())
    runtime.locale = () => 'zh'
    const result = await runGuardCommand(runtime, 'egress')
    const text = result.kind === 'success' ? (result.text ?? '') : ''
    expect(text).toContain('敏感信息守卫出站守卫')
    expect(text).toContain('已绑定')
    expect(text).toContain('隧道=2')
  })

  it('reports destinations from the audit log', async () => {
    const runtime = await egressRuntime(controller())
    const ts = Date.now() - 1000
    const line = (overrides: Record<string, unknown>) =>
      JSON.stringify({
        ts,
        phase: 'egress',
        event: 'connect',
        mode: 'monitor',
        ...overrides,
      })
    await writeFile(
      runtime.audit.path,
      [
        line({ host: 'api.example.com', port: 443, decision: 'allow', enforced: false }),
        line({ host: 'api.example.com', port: 443, decision: 'allow', enforced: false }),
        line({ host: 'blocked.example', port: 8443, decision: 'deny', enforced: true }),
      ].join('\n'),
    )

    const result = await runGuardCommand(runtime, 'egress report')
    expect(result.kind).toBe('success')
    const text = result.kind === 'success' ? (result.text ?? '') : ''
    expect(text).toContain('records: 3 connects, 1 blocked, 2 destinations')
    expect(text).toContain('api.example.com:443')
    expect(text).toContain('blocked.example:8443')
    expect(text).not.toContain('secret')
  })

  it('reports even while the guard is disabled', async () => {
    const { runtime } = await makeRuntime()
    await writeFile(
      runtime.audit.path,
      JSON.stringify({
        ts: Date.now() - 500,
        phase: 'egress',
        event: 'connect',
        host: 'old.example',
        port: 443,
        decision: 'allow',
        enforced: false,
      }),
    )
    const result = await runGuardCommand(runtime, 'egress report')
    expect(result.kind).toBe('success')
    expect(result.kind === 'success' ? result.text : '').toContain('old.example:443')
  })

  it('prints a suggested allowlist with --yaml', async () => {
    const runtime = await egressRuntime(controller())
    await writeFile(
      runtime.audit.path,
      JSON.stringify({
        ts: Date.now() - 500,
        phase: 'egress',
        event: 'connect',
        host: 'api.example.com',
        port: 443,
        decision: 'allow',
        enforced: false,
      }),
    )
    const result = await runGuardCommand(runtime, 'egress report --yaml')
    expect(result.kind).toBe('success')
    const text = result.kind === 'success' ? (result.text ?? '') : ''
    expect(text).toContain('egress:')
    expect(text).toContain('unknown: deny')
    expect(text).toContain("- 'api.example.com:443'")
  })

  it('rejects an invalid window and unknown flags', async () => {
    const runtime = await egressRuntime(controller())
    const bad = await runGuardCommand(runtime, 'egress report --since weekly')
    expect(bad.kind).toBe('error')
    expect(bad.kind === 'error' ? bad.text : '').toContain('--since accepts')

    const unknown = await runGuardCommand(runtime, 'egress report --nope')
    expect(unknown.kind).toBe('error')
    expect(unknown.kind === 'error' ? unknown.text : '').toContain('Usage:')
  })

  it('rejects an unknown egress subcommand with usage', async () => {
    const runtime = await egressRuntime(controller())
    const result = await runGuardCommand(runtime, 'egress bogus')
    expect(result.kind).toBe('error')
    expect(result.kind === 'error' ? result.text : '').toContain('Usage:')
  })
})
