/**
 * Dependency-free shell decomposition for argv-based policy rules. Tokens are
 * parsed for matching only: quotes and escapes are handled, variables are not
 * expanded, and nothing is ever executed.
 *
 * Pipeline signatures contain command base names only (e.g. `curl | sh`), so a
 * URL argument containing slashes cannot defeat the vendored `curl*|*sh`
 * baseline rule. `args` is an ordered prefix match; `anyArg` sees every
 * argument token and redirect target across pipe stages.
 * @module dsh-sensitive-guard/policy/argv
 */

export interface CommandSegment {
  command: string
  args: string[]
}

export interface ParsedArgv {
  /** First command word after sudo/env/builtin prefixes are stripped. */
  command: string
  /** First command's argument tokens, ordered (redirects excluded). */
  args: string[]
  /** Command base names across pipe stages, joined into a normalized signature. */
  pipeline: string
  /** Every argument token across stages, options and redirect targets included. */
  anyTokens: string[]
  /** Non-option argument and redirect-target tokens, used as path evidence. */
  pathTokens: string[]
  /** `bash -c`/`sh -c` payloads, recursively parsed (depth-capped). */
  nested: ParsedArgv[]
}

/** Total shell nesting levels parsed, including the outermost command. */
const DEFAULT_MAX_DEPTH = 3

const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'fish', 'ksh', 'ash'])

const ENV_ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/

const SUDO_VALUE_OPTIONS = new Set([
  '-u',
  '-g',
  '-p',
  '-C',
  '-h',
  '-r',
  '-t',
  '-U',
  '-T',
  '-R',
  '-D',
  '-c',
  '--user',
  '--group',
  '--prompt',
  '--close-from',
  '--host',
  '--role',
  '--type',
  '--other-user',
  '--command-timeout',
  '--chdir',
  '--chroot',
  '--login-class',
])

const ENV_VALUE_OPTIONS = new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string'])

type Token =
  | { kind: 'word'; value: string }
  | { kind: 'op'; value: string }
  | { kind: 'redir'; takesTarget: boolean }

interface RawSegment {
  words: string[]
  redirects: string[]
  separator: string
}

interface StrippedSegment extends CommandSegment {
  separator: string
  redirects: string[]
}

/** Base name of a command word; accepts both slash styles for testability. */
export function commandBasename(word: string): string {
  const normalized = word.replaceAll('\\', '/')
  const index = normalized.lastIndexOf('/')
  const base = index >= 0 ? normalized.slice(index + 1) : normalized
  return base.length > 0 ? base : word
}

function isEnvAssignment(word: string): boolean {
  return ENV_ASSIGN.test(word)
}

function lex(input: string): Token[] {
  const tokens: Token[] = []
  let index = 0
  const length = input.length

  while (index < length) {
    const char = input[index]!
    if (char === ' ' || char === '\t' || char === '\n' || char === '\r') {
      index += 1
      continue
    }
    // A comment starts only at a token boundary.
    if (char === '#') break

    const rest = input.slice(index)

    if (rest.startsWith('||')) {
      tokens.push({ kind: 'op', value: '||' })
      index += 2
      continue
    }
    if (rest.startsWith('&&')) {
      tokens.push({ kind: 'op', value: '&&' })
      index += 2
      continue
    }
    if (rest.startsWith('&>>')) {
      tokens.push({ kind: 'redir', takesTarget: true })
      index += 3
      continue
    }
    if (rest.startsWith('&>')) {
      tokens.push({ kind: 'redir', takesTarget: true })
      index += 2
      continue
    }

    // File-descriptor redirection: 2>, 2>>, 2>&1, plus the plain forms.
    const fd = /^(\d*)(>>|<<|>|<)(&(?:\d+|-))?/.exec(rest)
    if (fd !== null && (fd[1] !== '' || char === '>' || char === '<')) {
      tokens.push({ kind: 'redir', takesTarget: fd[3] === undefined })
      index += fd[0].length
      continue
    }

    if (char === '|' || char === ';' || char === '&') {
      tokens.push({ kind: 'op', value: char })
      index += 1
      continue
    }

    let value = ''
    let sawPart = false
    while (index < length) {
      const current = input[index]!
      if (
        current === ' ' ||
        current === '\t' ||
        current === '\n' ||
        current === '\r' ||
        current === '|' ||
        current === '&' ||
        current === ';' ||
        current === '<' ||
        current === '>'
      ) {
        break
      }
      if (current === "'") {
        sawPart = true
        index += 1
        while (index < length && input[index] !== "'") {
          value += input[index]!
          index += 1
        }
        if (index < length) index += 1
        continue
      }
      if (current === '"') {
        sawPart = true
        index += 1
        while (index < length) {
          const inner = input[index]!
          if (inner === '"') {
            index += 1
            break
          }
          if (inner === '\\' && index + 1 < length) {
            const next = input[index + 1]!
            if (next === '"' || next === '\\' || next === '$' || next === '`') {
              value += next
              index += 2
              continue
            }
            value += inner
            index += 1
            continue
          }
          value += inner
          index += 1
        }
        continue
      }
      if (current === '\\') {
        sawPart = true
        if (index + 1 < length) {
          const next = input[index + 1]!
          if (next !== '\n') value += next
          index += 2
        } else {
          index += 1
        }
        continue
      }
      value += current
      sawPart = true
      index += 1
    }
    if (sawPart) tokens.push({ kind: 'word', value })
  }
  return tokens
}

function splitSegments(tokens: readonly Token[]): RawSegment[] {
  const segments: RawSegment[] = []
  let words: string[] = []
  let redirects: string[] = []
  let pendingTarget = false

  for (const token of tokens) {
    if (token.kind === 'word') {
      if (pendingTarget) {
        pendingTarget = false
        redirects.push(token.value)
        continue
      }
      words.push(token.value)
      continue
    }
    if (token.kind === 'redir') {
      pendingTarget = token.takesTarget
      continue
    }
    segments.push({ words, redirects, separator: token.value })
    words = []
    redirects = []
    pendingTarget = false
  }
  segments.push({ words, redirects, separator: '' })
  return segments
}

function skipOptions(
  words: readonly string[],
  start: number,
  valueOptions: ReadonlySet<string>,
  allowAssignments: boolean,
): number {
  let index = start
  while (index < words.length) {
    const word = words[index]!
    if (word === '--') return index + 1
    if (allowAssignments && isEnvAssignment(word)) {
      index += 1
      continue
    }
    if (!word.startsWith('-')) return index
    if (word.includes('=')) {
      index += 1
      continue
    }
    index += valueOptions.has(word) ? 2 : 1
  }
  return index
}

function stripPrefixes(words: readonly string[]): CommandSegment {
  let index = 0
  while (index < words.length) {
    const word = words[index]!
    if (isEnvAssignment(word)) {
      index += 1
      continue
    }
    const base = commandBasename(word)
    if (base === 'sudo') {
      index = skipOptions(words, index + 1, SUDO_VALUE_OPTIONS, false)
      continue
    }
    if (base === 'env') {
      index = skipOptions(words, index + 1, ENV_VALUE_OPTIONS, true)
      continue
    }
    if (
      base === 'command' ||
      base === 'builtin' ||
      base === 'nohup' ||
      base === 'exec' ||
      base === 'time'
    ) {
      index += 1
      continue
    }
    break
  }
  const command = words[index]
  if (command === undefined) return { command: '', args: [] }
  return { command, args: words.slice(index + 1) }
}

/** Extract the payload of `bash -c` (including combined flags such as `-lc`). */
function shellPayload(segment: CommandSegment): string | undefined {
  if (!SHELLS.has(commandBasename(segment.command))) return undefined
  for (let index = 0; index < segment.args.length; index += 1) {
    const arg = segment.args[index]!
    const isCommandFlag = arg === '--command' || /^-[A-Za-z]*c[A-Za-z]*$/.test(arg)
    if (!isCommandFlag) continue
    const payload = segment.args[index + 1]
    if (payload !== undefined && payload.length > 0) return payload
  }
  return undefined
}

function isPathLikeToken(token: string): boolean {
  return token.length > 0 && !token.startsWith('-') && !token.includes('://')
}

function parseAtDepth(input: string, depth: number, maxDepth: number): ParsedArgv {
  const rawSegments = splitSegments(lex(input))
  const segments: StrippedSegment[] = []
  let lastSeparator = ''

  for (const raw of rawSegments) {
    const stripped = stripPrefixes(raw.words)
    if (stripped.command.length === 0) {
      if (raw.separator.length > 0) lastSeparator = raw.separator
      continue
    }
    segments.push({ ...stripped, separator: lastSeparator, redirects: raw.redirects })
    lastSeparator = raw.separator
  }

  const anyTokens: string[] = []
  const pathTokens: string[] = []
  for (const segment of segments) {
    for (const token of segment.args) {
      anyTokens.push(token)
      if (isPathLikeToken(token)) pathTokens.push(token)
    }
    for (const target of segment.redirects) {
      anyTokens.push(target)
      if (isPathLikeToken(target)) pathTokens.push(target)
    }
  }

  const pipeline = segments
    .map((segment, index) => {
      const name = commandBasename(segment.command)
      if (index === 0) return name
      const separator = segment.separator.length > 0 ? segment.separator : '|'
      return separator + ' ' + name
    })
    .join(' ')

  const first = segments[0]
  const parsed: ParsedArgv = {
    command: first?.command ?? '',
    args: first?.args ?? [],
    pipeline,
    anyTokens,
    pathTokens,
    nested: [],
  }

  if (depth < maxDepth) {
    for (const segment of segments) {
      const payload = shellPayload(segment)
      if (payload !== undefined) parsed.nested.push(parseAtDepth(payload, depth + 1, maxDepth))
    }
  }
  return parsed
}

/** Parse one shell command line. Safe for untrusted input; never executes. */
export function parseCommand(input: string, options?: { maxDepth?: number }): ParsedArgv {
  const requested = options?.maxDepth ?? DEFAULT_MAX_DEPTH
  const maxDepth = Math.max(1, Math.min(requested, 8))
  return parseAtDepth(input, 1, maxDepth)
}

/** The parsed argv plus every recursively parsed `bash -c` payload. */
export function flattenArgvs(parsed: ParsedArgv): ParsedArgv[] {
  const out: ParsedArgv[] = [parsed]
  for (const child of parsed.nested) out.push(...flattenArgvs(child))
  return out
}
