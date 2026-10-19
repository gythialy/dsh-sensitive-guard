/**
 * Policy rule model and compiled forms. Raw rules mirror the YAML accepted in
 * `<project>/.dsh/rules.yaml`; compiled rules hold pre-compiled glob matchers so
 * evaluation never recompiles user input.
 * @module dsh-sensitive-guard/policy/types
 */
import type { GuardAction } from '../contracts.js'

/** Where a compiled rule came from, for diagnostics and audit. */
export type RuleSource = 'user' | 'config' | 'builtin'

/** Shell decomposition constraints; every listed sub-dimension must match. */
export interface RuleArgv {
  /** Command word glob(s), matched against both the raw and base name. */
  command?: string | string[]
  /** Ordered prefix match against the parsed argument tokens. */
  args?: string[]
  /** Positive patterns must match one token; `!`-prefixed patterns must match none. */
  anyArg?: string[]
  /** Glob over the normalized pipeline signature (command words joined by pipes). */
  pipeline?: string | string[]
}

/** Platform gate; never evidence on its own. */
export interface RuleWhen {
  platform?: NodeJS.Platform[]
}

/** AND across dimensions, OR inside each dimension. */
export interface RuleMatch {
  tools?: string[]
  /** Argument keys (dot paths for nested scalars) mapped to accepted glob values. */
  params?: Record<string, string[]>
  /** Globs matched against normalized paths extracted from arguments and shell tokens. */
  paths?: string[]
  argv?: RuleArgv
  agents?: string[]
  when?: RuleWhen
}

/** One rule as authored in YAML, before validation and compilation. */
export interface Rule {
  id?: string
  action: GuardAction
  priority?: number
  match: RuleMatch
  reason?: string
  enabled?: boolean
  enforce?: boolean
  tags?: string[]
}

/** Precompiled glob matcher. */
export type Matcher = (input: string) => boolean

export interface CompiledParams {
  key: string
  patterns: Matcher[]
}

export interface CompiledArgv {
  command: Matcher[]
  args: Matcher[]
  anyArg: Matcher[]
  notAnyArg: Matcher[]
  pipeline: Matcher[]
}

export interface CompiledMatch {
  tools: Matcher[]
  params: CompiledParams[]
  paths: Matcher[]
  argv?: CompiledArgv
  agents: Matcher[]
  /** Allowed platforms; undefined means every platform. */
  platforms?: string[]
}

export interface CompiledRule {
  id: string
  action: GuardAction
  priority: number
  reason?: string
  /** False for a gray-release rule: report the match but do not enforce it. */
  enforce: boolean
  tags: string[]
  source: RuleSource
  match: CompiledMatch
}

/** Result of loading and compiling every rule source for one cwd. */
export interface LoadedRuleSet {
  rules: CompiledRule[]
  /** Generated `paths.allow` + `paths.deny` rules. */
  pathRuleCount: number
  builtinCount: number
  userCount: number
}
