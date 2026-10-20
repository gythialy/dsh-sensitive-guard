import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  collectEgressReport,
  egressReportYaml,
  parseReportSince,
  rotationCandidates,
  summarizeEgressLines,
} from '../../../src/egress/report.js'

let dir: string

beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'sg-report-'))
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 20 })
})

const NOW = Date.UTC(2026, 9, 20, 12, 0, 0)

function record(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    ts: NOW - 1000,
    phase: 'egress',
    event: 'connect',
    host: 'api.example.com',
    port: 443,
    decision: 'allow',
    enforced: false,
    mode: 'monitor',
    ...overrides,
  })
}

describe('parseReportSince', () => {
  it('accepts relative windows', () => {
    expect(parseReportSince('30s', NOW)).toBe(NOW - 30_000)
    expect(parseReportSince('15m', NOW)).toBe(NOW - 15 * 60_000)
    expect(parseReportSince('24h', NOW)).toBe(NOW - 24 * 60 * 60_000)
    expect(parseReportSince('7d', NOW)).toBe(NOW - 7 * 24 * 60 * 60_000)
  })

  it('accepts an absolute ISO date and defaults to 7d', () => {
    expect(parseReportSince('2026-10-01T00:00:00Z', NOW)).toBe(Date.UTC(2026, 9, 1))
    expect(parseReportSince(undefined, NOW)).toBe(NOW - 7 * 24 * 60 * 60_000)
    expect(parseReportSince('', NOW)).toBeUndefined()
  })

  it('rejects unknown shapes instead of guessing', () => {
    expect(parseReportSince('weekly', NOW)).toBeUndefined()
    expect(parseReportSince('0d', NOW)).toBeUndefined()
    expect(parseReportSince('7w', NOW)).toBeUndefined()
  })
})

describe('summarizeEgressLines', () => {
  it('aggregates connects per destination and tallies blocked ones', () => {
    const summary = summarizeEgressLines(
      [
        record(),
        record({ ts: NOW - 500 }),
        record({ host: 'registry.example.com', port: 443 }),
        record({ host: 'blocked.example', port: 8443, decision: 'deny', enforced: true }),
      ],
      NOW - 60_000,
    )
    expect(summary.connects).toBe(4)
    expect(summary.denied).toBe(1)
    expect(summary.entries[0]).toMatchObject({
      host: 'api.example.com',
      port: 443,
      connects: 2,
      allowed: 2,
      denied: 0,
    })
    expect(summary.entries.map((entry) => entry.host)).toEqual([
      'api.example.com',
      'blocked.example',
      'registry.example.com',
    ])
  })

  it('ignores other phases, events, malformed lines, and old records', () => {
    const summary = summarizeEgressLines(
      [
        '',
        '{not json',
        JSON.stringify({ ts: NOW, phase: 'decision', event: 'connect', host: 'x', port: 1 }),
        record({ phase: 'egress', event: 'close' }),
        record({ ts: NOW - 10 * 24 * 60 * 60_000 }),
        record({ port: '443' }),
        record({ host: '' }),
        record(),
      ],
      NOW - 60_000,
    )
    expect(summary.connects).toBe(1)
    expect(summary.entries).toHaveLength(1)
  })

  it('keeps the newest lastTs per destination', () => {
    const summary = summarizeEgressLines(
      [record({ ts: NOW - 1000 }), record({ ts: NOW - 10 })],
      NOW - 60_000,
    )
    expect(summary.entries[0]?.lastTs).toBe(NOW - 10)
  })
})

describe('collectEgressReport', () => {
  it('reads the active log and its rotations', async () => {
    const audit = path.join(dir, 'audit.jsonl')
    await writeFile(audit + '.1', record({ ts: NOW - 4000 }) + '\n', 'utf8')
    await writeFile(audit, record() + '\n' + record({ ts: NOW - 2000 }) + '\n', 'utf8')

    const report = await collectEgressReport(audit, { now: NOW, since: '7d' })
    expect(report.files).toBe(2)
    expect(report.connects).toBe(3)
    expect(report.truncated).toBe(false)
  })

  it('returns an empty report for a missing log', async () => {
    const report = await collectEgressReport(path.join(dir, 'absent.jsonl'), { now: NOW })
    expect(report.connects).toBe(0)
    expect(report.entries).toEqual([])
    expect(report.files).toBe(0)
  })

  it('applies the window and rejects an invalid one', async () => {
    const audit = path.join(dir, 'audit.jsonl')
    await writeFile(audit, record() + '\n' + record({ ts: NOW - 30 * 24 * 60 * 60_000 }) + '\n')
    const report = await collectEgressReport(audit, { now: NOW, since: '7d' })
    expect(report.connects).toBe(1)
    await expect(collectEgressReport(audit, { since: 'nope' })).rejects.toThrow('invalid-since')
  })

  it('marks the report truncated when the byte budget cuts rotations', async () => {
    const audit = path.join(dir, 'audit.jsonl')
    await writeFile(audit + '.1', record({ ts: NOW - 4000 }) + '\n', 'utf8')
    await writeFile(audit, record() + '\n', 'utf8')
    const report = await collectEgressReport(audit, { now: NOW, maxBytes: 200 })
    expect(report.truncated).toBe(true)
  })

  it('lists rotation candidates oldest first', () => {
    const files = rotationCandidates('/tmp/audit.jsonl')
    expect(files[0]).toBe('/tmp/audit.jsonl.5')
    expect(files[files.length - 1]).toBe('/tmp/audit.jsonl')
  })
})

describe('egressReportYaml', () => {
  it('prints a pasteable allowlist with the deny default', async () => {
    const audit = path.join(dir, 'audit.jsonl')
    await writeFile(
      audit,
      [
        record({ host: 'api.example.com', port: 443 }),
        record({ host: 'api.example.com', port: 443 }),
        record({ host: 'blocked.example', port: 8443, decision: 'deny', enforced: true }),
      ].join('\n'),
    )
    const report = await collectEgressReport(audit, { now: NOW })
    const yaml = egressReportYaml(report)
    expect(yaml).toContain('egress:')
    expect(yaml).toContain('unknown: deny')
    expect(yaml).toContain("- 'api.example.com:443'")
    expect(yaml).toContain("- 'blocked.example:8443'")
    expect(yaml).toContain('# Sensitive Guard egress report: 3 connect(s)')
  })

  it('prints an empty allow list when there is no traffic', async () => {
    const report = await collectEgressReport(path.join(dir, 'absent.jsonl'), { now: NOW })
    expect(egressReportYaml(report)).toContain('    []')
  })
})
