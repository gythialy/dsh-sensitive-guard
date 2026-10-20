/**
 * Shared, dependency-light contracts between the guard's policy engine,
 * redaction engine, hooks, and audit writer. These types intentionally avoid
 * importing host packages so each module can be unit-tested in isolation.
 * @module dsh-sensitive-guard/contracts
 */

/** Redaction depth: tier 0 only, tiers 0-1, or every tier including PII. */
export type Level = 'minimal' | 'balanced' | 'aggressive'

/** One policy decision, independent of the host's richer decision union. */
export type GuardAction = 'allow' | 'deny' | 'ask'

/** Guard mode: audit only (`monitor`) or enforce decisions (`enforce`). */
export type GuardMode = 'monitor' | 'enforce'

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue }

/** Structural content block; only `type: 'text'` blocks are rewritten. */
export interface BlockLike {
  type: string
  text?: string
  [key: string]: unknown
}

/** One category of redaction, aggregated per scan for audit purposes. */
export interface RedactionHit {
  category: string
  count: number
  /** PII categories use keyed pseudonyms instead of secret placeholders. */
  pii?: boolean
  /** Secret placeholder ids minted for this hit (never the original value). */
  placeholderIds?: string[]
}

export interface TextRedaction {
  text: string
  changed: boolean
  hits: RedactionHit[]
  /** True when `limits.maxScanBytes` forced a head/tail scan. */
  truncated?: boolean
}

export interface ValueRedaction {
  value: JsonValue
  changed: boolean
  hits: RedactionHit[]
  truncated?: boolean
}

export interface ContentRedaction {
  content: BlockLike[]
  changed: boolean
  hits: RedactionHit[]
  truncated?: boolean
}

/** Text redactor used by every hook. Implementations must be idempotent. */
export interface Redactor {
  /** Cheap detection without allocating rewritten text. */
  scan(text: string, level: Level): boolean
  redactText(text: string, level: Level): TextRedaction
  redactValue(value: JsonValue, level: Level): ValueRedaction
  redactBlocks(content: readonly BlockLike[], level: Level): ContentRedaction
  /**
   * Resolve a PII placeholder to its original value when the redactor was
   * created with `pii.restore` enabled. Secrets never resolve.
   */
  restore(placeholder: string): string | undefined
  /** Total number of configured rules, exposed for startup diagnostics. */
  readonly ruleCount: number
}

/** One pending tool call as seen by the policy engine. */
export interface PolicyInput {
  tool: string
  args: unknown
  /** Host agent id when available. */
  agentId?: string
  /** Session working directory used to resolve relative paths. */
  cwd?: string
  platform?: NodeJS.Platform
}

/** Result of evaluating the rule set for one tool call. */
export interface PolicyDecision {
  action: GuardAction
  /** Whether an actual rule matched; false for the default decision. */
  matched: boolean
  ruleId?: string
  /** Model-facing reason. Must never contain the matched secret or full path. */
  reason?: string
  /** Plaintext evidence for internal hashing only; never log or return it. */
  paths?: string[]
  command?: string
  /** True when the match came from a network rule. */
  network?: boolean
  /** Tags from the matched rule, used only to classify the prompt. */
  tags?: string[]
  /** True when evaluation threw and the fail-closed default was applied. */
  failure?: boolean
  /** Per-rule gray release: false reports but does not enforce this match. */
  enforce?: boolean
}

export interface PolicyEngine {
  evaluate(input: PolicyInput): PolicyDecision
  readonly ruleCount: number
}

/** Minimal logger surface; the Cordis context logger satisfies it structurally. */
export interface Logger {
  info(message: string): void
  warn(message: string): void
  debug?(message: string): void
}
