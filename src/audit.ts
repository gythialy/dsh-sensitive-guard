/**
 * Append-only JSONL audit log. Records contain rule ids, counts, hashes, and
 * placeholder ids only — never original content, secrets, or full paths.
 * @module dsh-sensitive-guard/audit
 */
import { chmod, mkdir, open, rename, stat, unlink } from 'node:fs/promises'
import path from 'node:path'
import type { GuardAction, Logger } from './contracts.js'
import { resolveConfiguredPath } from './util/paths.js'

export interface AuditOptions {
  enabled: boolean
  path: string
  rotateBytes: number
  logger: Logger
  cwd?: string
  home?: string
}

export interface DecisionRecord {
  session?: string
  tool: string
  decision: GuardAction
  rule?: string
  mode: 'monitor' | 'enforce'
  action: 'allowed' | 'blocked' | 'asked' | 'monitored'
  argsHash?: string
  pathHash?: string
  ruleCount?: number
}

export interface RedactRecord {
  session?: string
  tool?: string
  category: string
  count: number
  placeholderIds?: string[]
  truncated?: boolean
  spillBypassed?: boolean
  /** Hook arm that produced the redaction (distinct from the log phase). */
  hook: 'pre-step' | 'post-execute' | 'ptc-log' | 'system-prompt'
}

export interface ErrorRecord {
  session?: string
  tool?: string
  message: string
}

interface JsonlRecord {
  ts: number
  phase: 'decision' | 'redact' | 'error'
  [key: string]: unknown
}

const MAX_ROTATED_FILES = 5

/**
 * Serialized writer with size-based rotation. All failures are contained: the
 * guard must never break a tool call because the audit sink is unavailable.
 */
export class AuditLog {
  private readonly file: string
  private readonly options: AuditOptions
  private pending: Promise<void> = Promise.resolve()
  private disabled = false
  private warned = false

  constructor(options: AuditOptions) {
    this.options = options
    this.file = resolveConfiguredPath(options.path, options.cwd ?? process.cwd(), options.home)
  }

  /** Resolved log path; exposed for tests and diagnostics (not model-facing). */
  get path(): string {
    return this.file
  }

  decision(record: DecisionRecord): void {
    this.enqueue({ ts: Date.now(), phase: 'decision', ...record })
  }

  redact(record: RedactRecord): void {
    this.enqueue({ ts: Date.now(), phase: 'redact', ...record })
  }

  error(record: ErrorRecord): void {
    this.enqueue({ ts: Date.now(), phase: 'error', ...record })
  }

  /** Wait until every queued record has settled; safe to call from tests. */
  async flush(): Promise<void> {
    await this.pending
  }

  private enqueue(record: JsonlRecord): void {
    if (!this.options.enabled || this.disabled) return
    this.pending = this.pending
      .then(() => this.append(record))
      .catch((error: unknown) => {
        this.disabled = true
        if (!this.warned) {
          this.warned = true
          this.options.logger.warn(
            `sensitive-guard: audit log disabled after a write failure (${error instanceof Error ? error.name : 'error'})`,
          )
        }
      })
  }

  private async append(record: JsonlRecord): Promise<void> {
    const line = JSON.stringify(record) + '\n'
    await mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 })
    await this.rotateIfNeeded(Buffer.byteLength(line, 'utf8'))
    const handle = await open(this.file, 'a', 0o600)
    try {
      await handle.write(line, undefined, 'utf8')
    } finally {
      await handle.close()
    }
    // 'a' preserves an existing file's mode; enforce 0600 on every append.
    await chmod(this.file, 0o600).catch(() => undefined)
  }

  private async rotateIfNeeded(incomingBytes: number): Promise<void> {
    let size = 0
    try {
      size = (await stat(this.file)).size
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    }
    if (size === 0 || size + incomingBytes <= this.options.rotateBytes) return

    await unlink(this.file + '.' + MAX_ROTATED_FILES).catch(() => undefined)
    for (let index = MAX_ROTATED_FILES - 1; index >= 1; index -= 1) {
      await rename(this.file + '.' + index, this.file + '.' + (index + 1)).catch(() => undefined)
    }
    await rename(this.file, this.file + '.1').catch((error: unknown) => {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    })
  }
}
