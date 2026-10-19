/**
 * Rule loading: project YAML, generated path rules, and the vendored baseline.
 * Validation and glob compilation happen once per cwd and are cached; invalid
 * input throws (fail loud) instead of silently allowing a call.
 * @module dsh-sensitive-guard/policy/rules
 */
import { readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse as parseYaml } from 'yaml'
import type { GuardAction } from '../contracts.js'
import type { GuardConfig } from '../config.js'
import { resolveConfiguredPath } from '../util/paths.js'
import { compileGlob, compileGlobs } from './glob.js'
import { expandPathString } from './paths.js'
import type {
  CompiledArgv,
  CompiledMatch,
  CompiledParams,
  CompiledRule,
  LoadedRuleSet,
  Rule,
  RuleArgv,
  RuleMatch,
  RuleSource,
  RuleWhen,
} from './types.js'

const BASELINE_FILE = fileURLToPath(new URL('./baseline.yaml', import.meta.url))

const VALID_ACTIONS = new Set<string>(['allow', 'deny', 'ask'])

const VALID_PLATFORMS = new Set<string>([
  'aix',
  'android',
  'darwin',
  'freebsd',
  'haiku',
  'linux',
  'openbsd',
  'sunos',
  'win32',
  'cygwin',
  'netbsd',
])

type UnknownRecord = Record<string, unknown>

function isRecord(value: unknown): value is UnknownRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function invalid(label: string, index: number, detail: string): never {
  throw new Error(`sensitive-guard: invalid rule at index ${index} in ${label}: ${detail}`)
}

function stringArray(
  value: unknown,
  label: string,
  index: number,
  field: string,
): string[] | undefined {
  if (value === undefined) return undefined
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    !value.every((item) => typeof item === 'string' && item.length > 0)
  ) {
    invalid(label, index, field + ' must be a non-empty array of strings')
  }
  return value as string[]
}

function tagsArray(value: unknown, label: string, index: number): string[] | undefined {
  if (value === undefined) return undefined
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
    invalid(label, index, 'tags must be an array of strings')
  }
  return value as string[]
}

function patternList(
  value: unknown,
  label: string,
  index: number,
  field: string,
): string | string[] | undefined {
  if (value === undefined) return undefined
  if (typeof value === 'string') {
    if (value.length === 0) invalid(label, index, field + ' must not be empty')
    return value
  }
  return stringArray(value, label, index, field)
}

function validateArgv(value: unknown, label: string, index: number): RuleArgv {
  if (!isRecord(value)) invalid(label, index, 'match.argv must be a mapping')

  const argv: RuleArgv = {}
  const command = patternList(value['command'], label, index, 'match.argv.command')
  if (command !== undefined) argv.command = command

  const args = stringArray(value['args'], label, index, 'match.argv.args')
  if (args !== undefined) argv.args = args

  const anyArg = stringArray(value['anyArg'], label, index, 'match.argv.anyArg')
  if (anyArg !== undefined) {
    for (const pattern of anyArg) {
      if (pattern === '!') invalid(label, index, 'match.argv.anyArg pattern "!" is not valid')
    }
    argv.anyArg = anyArg
  }

  const pipeline = patternList(value['pipeline'], label, index, 'match.argv.pipeline')
  if (pipeline !== undefined) argv.pipeline = pipeline

  if (
    argv.command === undefined &&
    argv.args === undefined &&
    argv.anyArg === undefined &&
    argv.pipeline === undefined
  ) {
    invalid(label, index, 'match.argv must constrain command, args, anyArg, or pipeline')
  }
  return argv
}

function validateParams(
  value: unknown,
  label: string,
  index: number,
): Record<string, string[]> | undefined {
  if (value === undefined) return undefined
  if (!isRecord(value)) invalid(label, index, 'match.params must be a mapping')
  const params: Record<string, string[]> = {}
  for (const [key, patternsValue] of Object.entries(value)) {
    if (key.length === 0) invalid(label, index, 'match.params keys must not be empty')
    const patterns = stringArray(patternsValue, label, index, 'match.params.' + key)
    if (patterns === undefined) invalid(label, index, 'match.params.' + key + ' must be an array')
    params[key] = patterns
  }
  return params
}

function validateWhen(value: unknown, label: string, index: number): RuleWhen | undefined {
  if (value === undefined) return undefined
  if (!isRecord(value)) invalid(label, index, 'match.when must be a mapping')
  const when: RuleWhen = {}
  const platforms = stringArray(value['platform'], label, index, 'match.when.platform')
  if (platforms !== undefined) {
    for (const platform of platforms) {
      if (!VALID_PLATFORMS.has(platform)) {
        invalid(label, index, 'unknown platform "' + platform + '" in match.when.platform')
      }
    }
    when.platform = platforms as NodeJS.Platform[]
  }
  return when
}

function validateMatch(value: unknown, label: string, index: number): RuleMatch {
  if (!isRecord(value)) invalid(label, index, 'match must be a mapping')

  const match: RuleMatch = {}
  const tools = stringArray(value['tools'], label, index, 'match.tools')
  if (tools !== undefined) match.tools = tools

  const paths = stringArray(value['paths'], label, index, 'match.paths')
  if (paths !== undefined) match.paths = paths

  const agents = stringArray(value['agents'], label, index, 'match.agents')
  if (agents !== undefined) match.agents = agents

  const params = validateParams(value['params'], label, index)
  if (params !== undefined) match.params = params

  if (value['argv'] !== undefined) match.argv = validateArgv(value['argv'], label, index)
  const when = validateWhen(value['when'], label, index)
  if (when !== undefined) match.when = when

  return match
}

function validateRule(raw: unknown, index: number, label: string): Rule {
  if (!isRecord(raw)) invalid(label, index, 'rule must be a mapping')

  const action = raw['action']
  if (typeof action !== 'string' || !VALID_ACTIONS.has(action)) {
    invalid(label, index, 'action must be one of allow, deny, ask')
  }

  const rule: Rule = {
    action: action as GuardAction,
    match: validateMatch(raw['match'], label, index),
  }

  const id = raw['id']
  if (id !== undefined) {
    if (typeof id !== 'string' || id.length === 0)
      invalid(label, index, 'id must be a non-empty string')
    rule.id = id
  }

  const priority = raw['priority']
  if (priority !== undefined) {
    if (typeof priority !== 'number' || !Number.isFinite(priority)) {
      invalid(label, index, 'priority must be a finite number')
    }
    rule.priority = priority
  }

  const reason = raw['reason']
  if (reason !== undefined) {
    if (typeof reason !== 'string' || reason.length === 0) {
      invalid(label, index, 'reason must be a non-empty string')
    }
    rule.reason = reason
  }

  const enabled = raw['enabled']
  if (enabled !== undefined) {
    if (typeof enabled !== 'boolean') invalid(label, index, 'enabled must be a boolean')
    rule.enabled = enabled
  }

  const enforce = raw['enforce']
  if (enforce !== undefined) {
    if (typeof enforce !== 'boolean') invalid(label, index, 'enforce must be a boolean')
    rule.enforce = enforce
  }

  const tags = tagsArray(raw['tags'], label, index)
  if (tags !== undefined) rule.tags = tags

  return rule
}

/** Parse and validate one YAML rule document. */
export function parseRuleDocument(text: string, label: string): Rule[] {
  let document: unknown
  try {
    document = parseYaml(text)
  } catch (error) {
    const message = error instanceof Error ? error.message.split('\n')[0] : 'unknown parse error'
    throw new Error(`sensitive-guard: invalid YAML in ${label}: ${message}`)
  }
  if (document === null || document === undefined) return []
  if (!isRecord(document)) {
    throw new Error(`sensitive-guard: ${label} must contain a mapping with a rules array`)
  }
  const rawRules = document['rules']
  if (rawRules === undefined || rawRules === null) return []
  if (!Array.isArray(rawRules))
    throw new Error(`sensitive-guard: rules in ${label} must be an array`)
  return rawRules.map((raw, index) => validateRule(raw, index, label))
}

function readRuleFile(file: string, label: string, missingOk: boolean): Rule[] {
  let text: string
  try {
    text = readFileSync(file, 'utf8')
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (missingOk && code === 'ENOENT') return []
    throw new Error(`sensitive-guard: cannot read ${label} (${code ?? 'error'})`)
  }
  return parseRuleDocument(text, label)
}

interface CompileSettings {
  id: string
  priority: number
  source: RuleSource
  platform: NodeJS.Platform
}

function compileParams(
  params: Record<string, string[]> | undefined,
  platform: NodeJS.Platform,
): CompiledParams[] {
  if (params === undefined) return []
  return Object.entries(params).map(([key, patterns]) => ({
    key,
    patterns: compileGlobs(patterns, { platform }),
  }))
}

function compileArgv(argv: RuleArgv, platform: NodeJS.Platform): CompiledArgv {
  const globOptions = { platform }
  const positive: string[] = []
  const negative: string[] = []
  for (const pattern of argv.anyArg ?? []) {
    if (pattern.startsWith('!')) negative.push(pattern.slice(1))
    else positive.push(pattern)
  }
  const command = argv.command === undefined ? [] : asPatterns(argv.command)
  const pipeline = argv.pipeline === undefined ? [] : asPatterns(argv.pipeline)
  return {
    command: compileGlobs(command, globOptions),
    args: compileGlobs(argv.args ?? [], globOptions),
    anyArg: compileGlobs(positive, globOptions),
    notAnyArg: compileGlobs(negative, globOptions),
    pipeline: compileGlobs(pipeline, globOptions),
  }
}

function asPatterns(value: string | string[]): string[] {
  return typeof value === 'string' ? [value] : value
}

function compileRule(rule: Rule, settings: CompileSettings): CompiledRule {
  const globOptions = { platform: settings.platform }
  const match: CompiledMatch = {
    tools: compileGlobs(rule.match.tools ?? [], globOptions),
    params: compileParams(rule.match.params, settings.platform),
    // Path patterns may use ~ or whitelisted variables; expand before compiling.
    paths: (rule.match.paths ?? []).map((pattern) =>
      compileGlob(expandPathString(pattern), globOptions),
    ),
    agents: compileGlobs(rule.match.agents ?? [], globOptions),
  }
  if (rule.match.argv !== undefined) match.argv = compileArgv(rule.match.argv, settings.platform)
  if (rule.match.when?.platform !== undefined) match.platforms = [...rule.match.when.platform]

  const compiled: CompiledRule = {
    id: settings.id,
    action: rule.action,
    priority: settings.priority,
    enforce: rule.enforce !== false,
    tags: rule.tags === undefined ? [] : [...rule.tags],
    source: settings.source,
    match,
  }
  if (rule.reason !== undefined) compiled.reason = rule.reason
  return compiled
}

function generatePathRules(config: GuardConfig, platform: NodeJS.Platform): CompiledRule[] {
  const rules: CompiledRule[] = []

  config.paths.allow.forEach((pattern, index) => {
    const rule: Rule = {
      action: 'allow',
      priority: -10,
      match: { paths: [pattern] },
      reason: 'This path is on the configured allow list',
    }
    rules.push(
      compileRule(rule, {
        id: `config-allow:${index}`,
        priority: -10,
        source: 'config',
        platform,
      }),
    )
  })

  config.paths.deny.forEach((pattern, index) => {
    const rule: Rule = {
      action: 'deny',
      priority: -20,
      match: { paths: [pattern] },
      reason:
        'This path is denied by configuration; ask the user or read a non-credential file instead',
    }
    rules.push(
      compileRule(rule, {
        id: `config-deny:${index}`,
        priority: -20,
        source: 'config',
        platform,
      }),
    )
  })

  return rules
}

let baselineRules: Rule[] | undefined

function loadBaselineRules(): Rule[] {
  baselineRules ??= readRuleFile(BASELINE_FILE, 'builtin baseline', false)
  return baselineRules
}

interface CacheEntry {
  signature: string
  mtimeMs: number
  size: number
  loaded: LoadedRuleSet
}

const ruleSetCache = new Map<string, CacheEntry>()

/** Drop every cached rule set; used by tests and config reloads. */
export function clearPolicyCache(): void {
  ruleSetCache.clear()
}

function statRulesFile(file: string): { mtimeMs: number; size: number } | undefined {
  try {
    const stats = statSync(file)
    return { mtimeMs: stats.mtimeMs, size: stats.size }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return undefined
    throw new Error(`sensitive-guard: cannot stat rules file (${code ?? 'error'})`)
  }
}

function buildRuleSet(
  config: GuardConfig,
  rulesFile: string,
  platform: NodeJS.Platform,
): LoadedRuleSet {
  const userRules: CompiledRule[] = []
  readRuleFile(rulesFile, 'project rules', true).forEach((rule, index) => {
    if (rule.enabled === false) return
    userRules.push(
      compileRule(rule, {
        id: rule.id ?? `user:${index}`,
        priority: rule.priority ?? 0,
        source: 'user',
        platform,
      }),
    )
  })

  const pathRules = generatePathRules(config, platform)

  const builtinRules: CompiledRule[] = []
  if (config.policy.builtin) {
    loadBaselineRules().forEach((rule, index) => {
      if (rule.enabled === false) return
      builtinRules.push(
        compileRule(rule, {
          id: rule.id ?? `builtin:${index}`,
          priority: rule.priority ?? -100,
          source: 'builtin',
          platform,
        }),
      )
    })
  }

  const rules = [...userRules, ...pathRules, ...builtinRules]
  if (rules.length > config.policy.maxRules) {
    throw new Error(
      `sensitive-guard: rule limit exceeded (${rules.length} > ${config.policy.maxRules}); trim rules or raise policy.maxRules`,
    )
  }

  // Stable sort: equal priorities keep declaration order, so user rules precede
  // generated and builtin rules at the same priority.
  rules.sort((left, right) => right.priority - left.priority)

  return {
    rules,
    pathRuleCount: pathRules.length,
    builtinCount: builtinRules.length,
    userCount: userRules.length,
  }
}

export interface LoadRuleSetOptions {
  config: GuardConfig
  cwd: string
  platform?: NodeJS.Platform
}

/**
 * Load and compile every rule for one session cwd. Results are cached per cwd
 * and invalidated when the rules file's mtime/size or the rule config changes.
 */
export function loadRuleSet(options: LoadRuleSetOptions): LoadedRuleSet {
  const platform = options.platform ?? process.platform
  const cwd = path.resolve(options.cwd)
  const rulesFile = resolveConfiguredPath(options.config.policy.rulesFile, cwd)
  const signature = JSON.stringify({
    rulesFile,
    builtin: options.config.policy.builtin,
    maxRules: options.config.policy.maxRules,
    allow: options.config.paths.allow,
    deny: options.config.paths.deny,
    platform,
  })

  const stats = statRulesFile(rulesFile)
  const mtimeMs = stats?.mtimeMs ?? -1
  const size = stats?.size ?? -1

  const cached = ruleSetCache.get(cwd)
  if (
    cached !== undefined &&
    cached.signature === signature &&
    cached.mtimeMs === mtimeMs &&
    cached.size === size
  ) {
    return cached.loaded
  }

  const loaded = buildRuleSet(options.config, rulesFile, platform)
  ruleSetCache.set(cwd, { signature, mtimeMs, size, loaded })
  return loaded
}
