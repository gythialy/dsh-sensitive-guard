/**
 * Evidence extraction from tool arguments. Walks the JSON tree once, picks out
 * path/command/URL keys, records scalar argument parameters, and normalizes
 * paths for glob matching. Values are never logged.
 * @module dsh-sensitive-guard/policy/evidence
 */
import type { PolicyInput } from '../contracts.js'
import { flattenArgvs, parseCommand, type ParsedArgv } from './argv.js'
import { pathCandidates } from './paths.js'

const PATH_KEYS = new Set(['path', 'file_path', 'filepath', 'file', 'dir', 'directory', 'target'])
const COMMAND_KEYS = new Set(['command', 'cmd', 'shell', 'script'])
const URL_KEYS = new Set(['url', 'uri', 'endpoint'])

const MAX_DEPTH = 6
const MAX_NODES = 10_000
const MAX_RAW = 512
const MAX_COMMANDS = 64
const MAX_URLS = 64
const MAX_PARAM_VALUES = 64
const MAX_PATHS = 256

export interface PolicyEvidence {
  tool: string
  agentId?: string
  cwd: string
  platform: NodeJS.Platform
  /** Argument keys (dot paths for nested scalars) to stringified values. */
  params: Map<string, string[]>
  /** Normalized absolute/relative/realpath candidates. */
  paths: string[]
  /** Raw command strings found in command-like arguments. */
  commands: string[]
  /** Parsed commands, including recursively parsed shell payloads. */
  argvs: ParsedArgv[]
  /** Absolute URLs found in URL-like arguments and shell tokens. */
  urls: string[]
}

function isScalar(value: unknown): value is string | number | boolean {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
}

function scalarToString(value: string | number | boolean): string {
  return typeof value === 'string' ? value : String(value)
}

/**
 * Collect all policy evidence for one tool call. The walk is bounded by node
 * count and depth so pathological argument trees stay cheap.
 */
export function collectEvidence(input: PolicyInput, platform: NodeJS.Platform): PolicyEvidence {
  const params = new Map<string, string[]>()
  const rawPaths: string[] = []
  const rawCommands: string[] = []
  const rawUrls: string[] = []

  const addParam = (key: string, value: string): void => {
    const existing = params.get(key)
    if (existing !== undefined) {
      if (existing.length < MAX_PARAM_VALUES) existing.push(value)
      return
    }
    params.set(key, [value])
  }

  const addRaw = (bucket: string[], value: string, limit: number): void => {
    if (value.length === 0 || bucket.length >= limit) return
    bucket.push(value)
  }

  const dispatchKey = (key: string, value: string): void => {
    const normalized = key.toLowerCase()
    if (PATH_KEYS.has(normalized)) {
      addRaw(rawPaths, value, MAX_RAW)
      return
    }
    if (COMMAND_KEYS.has(normalized)) {
      addRaw(rawCommands, value, MAX_COMMANDS)
      return
    }
    if (URL_KEYS.has(normalized)) addRaw(rawUrls, value, MAX_URLS)
  }

  const seen = new WeakSet<object>()
  let visited = 0

  const visit = (node: unknown, key: string | undefined, prefix: string, depth: number): void => {
    visited += 1
    if (visited > MAX_NODES || depth > MAX_DEPTH) return

    if (typeof node === 'string') {
      if (key !== undefined) dispatchKey(key, node)
      return
    }
    if (typeof node === 'number' || typeof node === 'boolean') return
    if (node === null || typeof node !== 'object') return

    if (Array.isArray(node)) {
      for (const item of node) {
        if (isScalar(item) && key !== undefined) dispatchKey(key, scalarToString(item))
        else visit(item, undefined, prefix, depth + 1)
      }
      return
    }

    if (seen.has(node)) return
    seen.add(node)

    for (const [childKey, childValue] of Object.entries(node)) {
      const dotted = prefix.length > 0 ? prefix + '.' + childKey : childKey
      if (isScalar(childValue)) {
        addParam(dotted, scalarToString(childValue))
      } else if (Array.isArray(childValue) && childValue.every(isScalar)) {
        for (const item of childValue)
          addParam(dotted, scalarToString(item as string | number | boolean))
      }
      visit(childValue, childKey, dotted, depth + 1)
    }
  }

  visit(input.args, undefined, '', 0)

  const cwd = input.cwd !== undefined && input.cwd.length > 0 ? input.cwd : process.cwd()
  const pathOptions = { cwd, platform }

  const paths = new Set<string>()
  const addPath = (raw: string): void => {
    if (paths.size >= MAX_PATHS) return
    for (const candidate of pathCandidates(raw, pathOptions)) {
      if (paths.size >= MAX_PATHS) return
      paths.add(candidate)
    }
  }
  for (const raw of rawPaths) addPath(raw)

  const commands: string[] = []
  const argvs: ParsedArgv[] = []
  const seenCommands = new Set<string>()
  for (const raw of rawCommands) {
    const trimmed = raw.trim()
    if (trimmed.length === 0) continue
    commands.push(raw)
    if (seenCommands.has(trimmed)) continue
    seenCommands.add(trimmed)
    for (const argv of flattenArgvs(parseCommand(trimmed))) {
      if (argv.command.length === 0) continue
      argvs.push(argv)
      for (const token of argv.pathTokens) addPath(token)
    }
  }

  const urls = new Set<string>()
  const addUrl = (value: string): void => {
    if (urls.size >= MAX_URLS) return
    if (!value.includes('://')) return
    urls.add(value)
  }
  for (const raw of rawUrls) addUrl(raw)
  for (const argv of argvs) {
    for (const token of argv.anyTokens) addUrl(token)
  }

  const evidence: PolicyEvidence = {
    tool: input.tool,
    cwd,
    platform,
    params,
    paths: [...paths],
    commands,
    argvs,
    urls: [...urls],
  }
  if (input.agentId !== undefined && input.agentId.length > 0) evidence.agentId = input.agentId
  return evidence
}
