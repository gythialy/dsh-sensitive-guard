/**
 * Standalone repository/CI scanner. It reuses the guard's compiled rule table
 * but never renders matched text: output contains only category, relative path,
 * count, and an optional line number.
 * @module dsh-sensitive-guard/cli/scan
 */
import { execFile } from 'node:child_process'
import { lstat, readFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import { promisify } from 'node:util'
import { resolveConfig } from '../config.js'
import { createRedactor } from '../redact/index.js'
import { noopLogger } from '../util/logger.js'

const execFileAsync = promisify(execFile)

export interface ScanFinding {
  file: string
  category: string
  count: number
  line?: number
}

export interface ScanOptions {
  cwd: string
  maxBytes: number
  json: boolean
  staged: boolean
  exitCode: boolean
  paths: string[]
}

export interface ScanResult {
  findings: ScanFinding[]
  scannedFiles: number
  skippedFiles: number
}

const DEFAULT_MAX_BYTES = 8 * 1024 * 1024
const IGNORED_DIRS = new Set([
  '.git',
  '.pnpm-store',
  '.cache',
  'coverage',
  'dist',
  'lib',
  'node_modules',
])

const HELP = `Usage: sensitive-guard-scan [options] [path...]

Scan files or directories with the dsh-sensitive-guard rule table.

Options:
  --json            Emit a JSON object instead of text lines
  --staged          Scan files staged in git (git diff --cached)
  --max-bytes N     Skip files larger than N bytes (default ${DEFAULT_MAX_BYTES})
  --no-exit-code    Always exit 0 even when findings exist
  -h, --help        Show this help

Exit codes: 0 clean, 1 findings, 2 usage/IO error.
Output never includes the matched value.
`

/** True when the first bytes look binary (NUL present). */
function looksBinary(buffer: Buffer): boolean {
  const limit = Math.min(buffer.length, 8192)
  for (let index = 0; index < limit; index += 1) {
    if (buffer[index] === 0) return true
  }
  return false
}

/** First line containing a line-scoped hit for the category, if any. */
function findLine(
  text: string,
  category: string,
  redactor: ReturnType<typeof createRedactor>,
): number | undefined {
  const lines = text.split('\n')
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? ''
    if (!redactor.scan(line, 'aggressive')) continue
    if (redactor.redactText(line, 'aggressive').hits.some((hit) => hit.category === category)) {
      return index + 1
    }
  }
  return undefined
}

async function collectFiles(target: string, out: string[], cwd: string): Promise<void> {
  let info
  try {
    info = await lstat(target)
  } catch {
    throw new Error('cannot read ' + path.relative(cwd, target))
  }
  if (info.isSymbolicLink()) return
  if (info.isFile()) {
    out.push(target)
    return
  }
  if (!info.isDirectory()) return
  if (IGNORED_DIRS.has(path.basename(target))) return
  const entries = await readdir(target, { withFileTypes: true })
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue
    await collectFiles(path.join(target, entry.name), out, cwd)
  }
}

async function stagedFiles(cwd: string): Promise<string[]> {
  const { stdout } = await execFileAsync('git', ['diff', '--cached', '--name-only', '-z'], { cwd })
  return stdout
    .split('\0')
    .filter((entry) => entry.length > 0)
    .map((entry) => path.resolve(cwd, entry))
}

/** Scan explicit paths (or the staged set) and return masked findings. */
export async function scanPaths(options: ScanOptions): Promise<ScanResult> {
  const config = resolveConfig({ pii: { enabled: true } })
  const redactor = createRedactor({ config, logger: noopLogger })
  const targets =
    options.paths.length > 0
      ? options.paths.map((entry) => path.resolve(options.cwd, entry))
      : options.staged
        ? await stagedFiles(options.cwd)
        : [options.cwd]

  const files: string[] = []
  for (const target of targets) await collectFiles(target, files, options.cwd)

  const findings: ScanFinding[] = []
  let scannedFiles = 0
  let skippedFiles = 0
  for (const file of files) {
    let buffer: Buffer
    try {
      buffer = await readFile(file)
    } catch {
      skippedFiles += 1
      continue
    }
    if (buffer.length > options.maxBytes || looksBinary(buffer)) {
      skippedFiles += 1
      continue
    }
    scannedFiles += 1
    const text = buffer.toString('utf8')
    const redacted = redactor.redactText(text, 'aggressive')
    if (redacted.hits.length === 0) continue
    const relative = path.relative(options.cwd, file).split(path.sep).join('/')
    for (const hit of redacted.hits) {
      const line = findLine(text, hit.category, redactor)
      findings.push({
        file: relative,
        category: hit.category,
        count: hit.count,
        ...(line === undefined ? {} : { line }),
      })
    }
  }
  return { findings, scannedFiles, skippedFiles }
}

function parseArgs(argv: string[]): { options?: ScanOptions; help?: boolean } {
  const options: ScanOptions = {
    cwd: process.cwd(),
    maxBytes: DEFAULT_MAX_BYTES,
    json: false,
    staged: false,
    exitCode: true,
    paths: [],
  }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index] ?? ''
    if (arg === '--help' || arg === '-h') return { help: true }
    if (arg === '--json') {
      options.json = true
      continue
    }
    if (arg === '--staged') {
      options.staged = true
      continue
    }
    if (arg === '--no-exit-code') {
      options.exitCode = false
      continue
    }
    if (arg === '--max-bytes') {
      const value = Number(argv[index + 1])
      if (!Number.isSafeInteger(value) || value <= 0) return {}
      options.maxBytes = value
      index += 1
      continue
    }
    if (arg.startsWith('--')) return {}
    options.paths.push(arg)
  }
  return { options }
}

/** CLI entry point; returns the process exit code. */
export async function main(argv: string[]): Promise<number> {
  const parsed = parseArgs(argv)
  if (parsed.help === true) {
    process.stdout.write(HELP)
    return 0
  }
  if (parsed.options === undefined) {
    process.stderr.write(HELP)
    return 2
  }

  let result: ScanResult
  try {
    result = await scanPaths(parsed.options)
  } catch (error) {
    process.stderr.write(
      'sensitive-guard-scan: ' + (error instanceof Error ? error.message : 'scan failed') + '\n',
    )
    return 2
  }

  if (parsed.options.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n')
  } else if (result.findings.length === 0) {
    process.stdout.write(`No findings in ${result.scannedFiles} file(s).\n`)
  } else {
    for (const finding of result.findings) {
      const line = finding.line === undefined ? '' : ` line ${finding.line}`
      process.stdout.write(`${finding.file}: ${finding.category} (${finding.count})${line}\n`)
    }
    process.stdout.write(
      `${result.findings.length} finding(s) in ${result.scannedFiles} file(s); ${result.skippedFiles} skipped.\n`,
    )
  }
  return parsed.options.exitCode && result.findings.length > 0 ? 1 : 0
}
