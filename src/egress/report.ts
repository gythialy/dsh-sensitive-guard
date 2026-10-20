/**
 * Read-only egress report over the audit log. It aggregates destination
 * `host:port` pairs so an allowlist can be built from what actually happened,
 * and it never reads paths, headers, or bodies: the audit holds none of them.
 * @module dsh-sensitive-guard/egress/report
 */
import { readFile } from 'node:fs/promises'

/** Rotated files kept by the audit writer. */
export const REPORT_ROTATIONS = 5

/** Default window when no `--since` value is given. */
export const DEFAULT_REPORT_SINCE = '7d'

/** Upper bound on bytes read across the active log and its rotations. */
export const MAX_REPORT_BYTES = 32 * 1024 * 1024

export interface EgressReportEntry {
  host: string
  port: number
  connects: number
  allowed: number
  denied: number
  lastTs: number
}

export interface EgressReport {
  /** Inclusive lower bound the records were filtered by. */
  sinceTs: number
  /** Timestamp used as "now" when the window was computed. */
  untilTs: number
  /** Number of log files that contributed. */
  files: number
  connects: number
  denied: number
  /** True when the byte budget stopped the oldest rotations from being read. */
  truncated: boolean
  /** Sorted by connect count, then host and port. */
  entries: EgressReportEntry[]
}

export interface CollectEgressReportOptions {
  since?: string | undefined
  now?: number
  maxBytes?: number
}

const SINCE_UNITS: Record<string, number> = {
  s: 1000,
  m: 60 * 1000,
  h: 60 * 60 * 1000,
  d: 24 * 60 * 60 * 1000,
}

/**
 * Parse a report window: `30s`, `15m`, `24h`, `7d`, or an ISO date. Returns
 * `undefined` for anything else so the caller can reject it instead of guessing.
 */
export function parseReportSince(value: string | undefined, now = Date.now()): number | undefined {
  const raw = (value ?? DEFAULT_REPORT_SINCE).trim()
  if (raw.length === 0) return undefined

  const relative = /^(\d+)([smhd])$/.exec(raw)
  if (relative !== null) {
    const amount = Number(relative[1])
    const unit = SINCE_UNITS[relative[2] ?? ''] ?? 0
    if (!Number.isSafeInteger(amount) || amount <= 0 || unit === 0) return undefined
    return now - amount * unit
  }

  const absolute = Date.parse(raw)
  return Number.isNaN(absolute) ? undefined : absolute
}

interface EgressLine {
  ts?: number
  phase?: string
  event?: string
  host?: string
  port?: number
  decision?: string
  enforced?: boolean
}

/**
 * Aggregate parsed audit lines. Malformed JSON and records from other phases or
 * events are skipped rather than counted, and `connect` is the only counted
 * event (a `close` record repeats the same tunnel).
 */
export function summarizeEgressLines(
  lines: Iterable<string>,
  sinceTs: number,
): Pick<EgressReport, 'connects' | 'denied' | 'entries'> {
  const byKey = new Map<string, EgressReportEntry>()
  let connects = 0
  let denied = 0

  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.length === 0) continue
    let record: EgressLine
    try {
      record = JSON.parse(trimmed) as EgressLine
    } catch {
      continue
    }
    if (record.phase !== 'egress' || record.event !== 'connect') continue
    if (typeof record.ts !== 'number' || record.ts < sinceTs) continue
    if (typeof record.host !== 'string' || record.host.length === 0) continue
    if (typeof record.port !== 'number' || !Number.isInteger(record.port)) continue

    connects += 1
    const enforced = record.enforced === true
    if (enforced) denied += 1

    const key = record.host + ':' + String(record.port)
    const entry = byKey.get(key)
    if (entry === undefined) {
      byKey.set(key, {
        host: record.host,
        port: record.port,
        connects: 1,
        allowed: record.decision === 'allow' ? 1 : 0,
        denied: enforced ? 1 : 0,
        lastTs: record.ts,
      })
      continue
    }
    entry.connects += 1
    if (record.decision === 'allow') entry.allowed += 1
    if (enforced) entry.denied += 1
    if (record.ts > entry.lastTs) entry.lastTs = record.ts
  }

  const entries = [...byKey.values()].sort(
    (left, right) =>
      right.connects - left.connects ||
      left.host.localeCompare(right.host) ||
      left.port - right.port,
  )
  return { connects, denied, entries }
}

async function readWithinBudget(
  files: readonly string[],
  maxBytes: number,
): Promise<{ text: string; files: number; truncated: boolean }> {
  const chunks: string[] = []
  let remaining = maxBytes
  let truncated = false
  let counted = 0

  for (const file of files) {
    let content: Buffer
    try {
      content = await readFile(file)
    } catch {
      continue
    }
    if (content.length > remaining) {
      // Read the newest tail of this file, then stop: older rotations are out.
      chunks.push(content.subarray(content.length - remaining).toString('utf8'))
      truncated = true
      counted += 1
      break
    }
    chunks.push(content.toString('utf8'))
    remaining -= content.length
    counted += 1
    if (remaining <= 0) {
      truncated = true
      break
    }
  }

  return { text: chunks.join('\n'), files: counted, truncated }
}

/** Rotation order oldest to newest, so a byte-budget cut drops the oldest. */
export function rotationCandidates(file: string): string[] {
  const files: string[] = []
  for (let index = REPORT_ROTATIONS; index >= 1; index -= 1) files.push(file + '.' + String(index))
  files.push(file)
  return files
}

/**
 * Read the active audit log plus its rotations and aggregate egress connects
 * inside the requested window. Unreadable files are skipped: a missing log is
 * an empty report, not an error.
 */
export async function collectEgressReport(
  auditPath: string,
  options: CollectEgressReportOptions = {},
): Promise<EgressReport> {
  const now = options.now ?? Date.now()
  const sinceTs = parseReportSince(options.since, now)
  if (sinceTs === undefined) throw new Error('invalid-since')

  const { text, files, truncated } = await readWithinBudget(
    rotationCandidates(auditPath),
    options.maxBytes ?? MAX_REPORT_BYTES,
  )
  const summary = summarizeEgressLines(text.split('\n'), sinceTs)
  return {
    sinceTs,
    untilTs: now,
    files,
    truncated,
    connects: summary.connects,
    denied: summary.denied,
    entries: summary.entries,
  }
}

function yamlEntry(entry: EgressReportEntry): string {
  const value = entry.host + ':' + String(entry.port)
  return "    - '" + value.replace(/'/g, "''") + "'"
}

/**
 * Suggested `egress` block for pasting into the profile patch. It is a
 * suggestion only: nothing is written to disk, and no destination is invented.
 */
export function egressReportYaml(report: EgressReport, limit = 100): string {
  const entries = report.entries.slice(0, limit)
  const since = new Date(report.sinceTs).toISOString()
  const lines = [
    '# Sensitive Guard egress report: ' + String(report.connects) + ' connect(s) since ' + since,
    '# Destinations only (host:port); review before enforcing.',
    'egress:',
    '  unknown: deny',
    '  allow:',
  ]
  if (entries.length === 0) lines.push('    []')
  for (const entry of entries) lines.push(yamlEntry(entry))
  if (report.entries.length > entries.length) {
    lines.push(
      '# ' + String(report.entries.length - entries.length) + ' more destination(s) omitted',
    )
  }
  return lines.join('\n')
}
