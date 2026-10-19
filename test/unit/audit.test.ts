import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { AuditLog } from '../../src/audit.js'
import type { Logger } from '../../src/contracts.js'

const tempDirs: string[] = []

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sg-audit-'))
  tempDirs.push(dir)
  return dir
}

function loggerWith(sink: string[]): Logger {
  return {
    info: (message) => sink.push('info:' + message),
    warn: (message) => sink.push('warn:' + message),
  }
}

afterEach(async () => {
  const { rm } = await import('node:fs/promises')
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

describe('AuditLog', () => {
  it('writes JSONL records with hashes and counts, never plaintext', async () => {
    const dir = await tempDir()
    const file = path.join(dir, 'audit.jsonl')
    const warnings: string[] = []
    const audit = new AuditLog({
      enabled: true,
      path: file,
      rotateBytes: 1024 * 1024,
      logger: loggerWith(warnings),
      cwd: dir,
    })

    audit.decision({
      tool: 'read',
      decision: 'deny',
      rule: 'deny-credential-paths',
      mode: 'enforce',
      action: 'blocked',
      pathHash: 'abc123',
      argsHash: 'def456',
      session: 'session-1',
    })
    audit.redact({
      hook: 'post-execute',
      tool: 'bash',
      category: 'aws-access-key',
      count: 2,
      placeholderIds: ['7Q2F'],
      spillBypassed: true,
    })
    audit.error({ tool: 'bash', message: 'Error' })
    await audit.flush()

    const lines = (await readFile(file, 'utf8')).trim().split('\n')
    expect(lines).toHaveLength(3)
    const records = lines.map((line) => JSON.parse(line) as Record<string, unknown>)
    expect(records[0]).toMatchObject({ phase: 'decision', tool: 'read', action: 'blocked' })
    expect(records[1]).toMatchObject({ phase: 'redact', category: 'aws-access-key', count: 2 })
    expect(records[2]).toMatchObject({ phase: 'error', message: 'Error' })
    for (const record of records) {
      expect(JSON.stringify(record)).not.toContain('AKIA')
      expect(JSON.stringify(record)).not.toContain('/Users/')
    }
    expect(warnings).toEqual([])
  })

  it('creates a 0700 directory and 0600 file', async () => {
    const dir = await tempDir()
    const file = path.join(dir, 'nested', 'audit.jsonl')
    const audit = new AuditLog({
      enabled: true,
      path: file,
      rotateBytes: 1024,
      logger: loggerWith([]),
      cwd: dir,
    })
    audit.decision({ tool: 'read', decision: 'allow', mode: 'enforce', action: 'allowed' })
    await audit.flush()

    expect((await stat(path.join(dir, 'nested'))).mode & 0o777).toBe(0o700)
    expect((await stat(file)).mode & 0o777).toBe(0o600)
  })

  it('rotates to .1 and keeps the active file bounded', async () => {
    const dir = await tempDir()
    const file = path.join(dir, 'audit.jsonl')
    const audit = new AuditLog({
      enabled: true,
      path: file,
      rotateBytes: 200,
      logger: loggerWith([]),
      cwd: dir,
    })
    for (let index = 0; index < 8; index += 1) {
      audit.decision({
        tool: 'read',
        decision: 'allow',
        mode: 'enforce',
        action: 'allowed',
        argsHash: 'x'.repeat(40),
      })
    }
    await audit.flush()
    expect((await stat(file + '.1')).isFile()).toBe(true)
    expect((await stat(file)).size).toBeLessThanOrEqual(260)
  })

  it('disables itself with one warning when the sink cannot be created', async () => {
    const dir = await tempDir()
    const blocker = path.join(dir, 'blocker')
    await writeFile(blocker, 'not a directory')
    const warnings: string[] = []
    const audit = new AuditLog({
      enabled: true,
      path: path.join(blocker, 'audit.jsonl'),
      rotateBytes: 1024,
      logger: loggerWith(warnings),
      cwd: dir,
    })
    audit.decision({ tool: 'read', decision: 'allow', mode: 'enforce', action: 'allowed' })
    audit.decision({ tool: 'read', decision: 'allow', mode: 'enforce', action: 'allowed' })
    await audit.flush()
    await audit.flush()

    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain('audit log disabled')
  })

  it('does not write when disabled', async () => {
    const dir = await tempDir()
    const file = path.join(dir, 'audit.jsonl')
    const audit = new AuditLog({
      enabled: false,
      path: file,
      rotateBytes: 1024,
      logger: loggerWith([]),
      cwd: dir,
    })
    audit.decision({ tool: 'read', decision: 'allow', mode: 'enforce', action: 'allowed' })
    await audit.flush()
    await expect(stat(file)).rejects.toMatchObject({ code: 'ENOENT' })
  })
})
