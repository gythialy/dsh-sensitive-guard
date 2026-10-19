/**
 * Redaction engine: applies the vendored rule table in order, skips existing
 * placeholders for idempotence, and rewrites text, JSON values, and content
 * blocks. Rules are compiled once at module load; per-call work only filters
 * the table by level and runs the global patterns from index 0.
 * @module dsh-sensitive-guard/redact/engine
 */
import type {
  BlockLike,
  ContentRedaction,
  JsonValue,
  Level,
  RedactionHit,
  Redactor,
  TextRedaction,
  ValueRedaction,
} from '../contracts.js'
import type { Pseudonymizer } from '../pseudonym/index.js'
import { secretPlaceholder, secretPlaceholderId } from './placeholders.js'
import { SECRET_RULES, maxTier, type CompiledSecretRule } from './rules.js'

export interface EngineOptions {
  maxScanBytes: number
  piiEnabled: boolean
  /** Lazily created so no key file is touched unless PII is actually scanned. */
  getPseudonymizer: () => Pseudonymizer
}

/** Existing placeholders must survive a second pass untouched. */
const PLACEHOLDER_PATTERN = /\[SECRET:[^\]\n]*\]|\[\[PII_[^\]\n]*\]\]/g

type PlaceholderRange = readonly [start: number, end: number]

interface HitBucket {
  category: string
  count: number
  pii: boolean
  ids: Set<string>
}

type HitAccumulator = Map<string, HitBucket>

interface RuleReplacement {
  text: string
  matches: number
  ids: string[]
}

/** Index ranges covered by placeholders already present in the text. */
function findPlaceholderRanges(text: string): PlaceholderRange[] {
  if (!text.includes('[SECRET:') && !text.includes('[[PII_')) return []
  const ranges: PlaceholderRange[] = []
  const pattern = new RegExp(PLACEHOLDER_PATTERN.source, 'g')
  let match: RegExpExecArray | null
  while ((match = pattern.exec(text)) !== null) {
    ranges.push([match.index, match.index + match[0].length])
  }
  return ranges
}

/** Binary search over sorted, non-overlapping placeholder ranges. */
function overlapsPlaceholder(
  ranges: readonly PlaceholderRange[],
  start: number,
  end: number,
): boolean {
  let low = 0
  let high = ranges.length - 1
  while (low <= high) {
    const middle = (low + high) >> 1
    const range = ranges[middle]
    if (range === undefined) return false
    if (range[1] <= start) low = middle + 1
    else if (range[0] >= end) high = middle - 1
    else return true
  }
  return false
}

function addHit(
  accumulator: HitAccumulator,
  category: string,
  count: number,
  pii: boolean,
  ids: readonly string[],
): void {
  let bucket = accumulator.get(category)
  if (bucket === undefined) {
    bucket = { category, count: 0, pii, ids: new Set() }
    accumulator.set(category, bucket)
  }
  bucket.count += count
  if (pii) bucket.pii = true
  for (const id of ids) bucket.ids.add(id)
}

function finalizeHits(accumulator: HitAccumulator): RedactionHit[] {
  const hits: RedactionHit[] = []
  for (const bucket of accumulator.values()) {
    const hit: RedactionHit = { category: bucket.category, count: bucket.count }
    if (bucket.pii) hit.pii = true
    if (bucket.ids.size > 0) hit.placeholderIds = [...bucket.ids]
    hits.push(hit)
  }
  return hits
}

/** Replace every validated, non-placeholder match of one rule. */
function replaceRule(
  text: string,
  rule: CompiledSecretRule,
  pseudonymizer: Pseudonymizer | undefined,
): RuleReplacement {
  const ranges = findPlaceholderRanges(text)
  const regex = rule.pattern
  const ids: string[] = []
  const seenIds = new Set<string>()
  let matches = 0
  let cursor = 0
  let output = ''
  let changed = false
  regex.lastIndex = 0
  try {
    let match: RegExpExecArray | null
    while ((match = regex.exec(text)) !== null) {
      const value = match[0]
      if (value.length === 0) {
        regex.lastIndex += 1
        continue
      }
      const start = match.index
      const end = start + value.length
      if (rule.validate !== undefined && !rule.validate(value)) continue
      if (ranges.length > 0 && overlapsPlaceholder(ranges, start, end)) continue
      let placeholder: string
      if (rule.pii === true) {
        // The active-rule filter guarantees a pseudonymizer for PII rules.
        if (pseudonymizer === undefined) continue
        placeholder = pseudonymizer.id(rule.category, value)
      } else {
        const id = secretPlaceholderId(value)
        placeholder = secretPlaceholder(rule.category, value)
        if (!seenIds.has(id)) {
          seenIds.add(id)
          ids.push(id)
        }
      }
      output += text.slice(cursor, start) + placeholder
      cursor = end
      matches += 1
      changed = true
    }
  } finally {
    regex.lastIndex = 0
  }
  if (!changed) return { text, matches: 0, ids: [] }
  output += text.slice(cursor)
  return { text: output, matches, ids }
}

/** Cheap detection over one window; stops at the first validated hit. */
function scanWindow(window: string, rules: readonly CompiledSecretRule[]): boolean {
  const ranges = findPlaceholderRanges(window)
  for (const rule of rules) {
    const regex = rule.pattern
    regex.lastIndex = 0
    try {
      let match: RegExpExecArray | null
      while ((match = regex.exec(window)) !== null) {
        const value = match[0]
        if (value.length === 0) {
          regex.lastIndex += 1
          continue
        }
        const start = match.index
        const end = start + value.length
        if (rule.validate !== undefined && !rule.validate(value)) continue
        if (ranges.length > 0 && overlapsPlaceholder(ranges, start, end)) continue
        return true
      }
    } finally {
      regex.lastIndex = 0
    }
  }
  return false
}

/** Bytes around each chunk boundary that are re-scanned for cross-boundary matches. */
const BOUNDARY_OVERLAP_BYTES = 16 * 1024

interface ScanSplit {
  /** Non-overlapping UTF-8-aligned chunks whose concatenation is the input. */
  chunks: string[]
  /** Windows straddling each boundary, used only for detection. */
  boundaryWindows: string[]
  /** True when the input needed more than one window. */
  truncated: boolean
}

/** Move forward to the next UTF-8 lead byte so a window never splits a rune. */
function alignForward(buffer: Buffer, index: number): number {
  let cursor = index
  while (cursor > 0 && cursor < buffer.length && ((buffer[cursor] ?? 0) & 0xc0) === 0x80)
    cursor += 1
  return cursor
}

/** Move back to the lead byte of the rune containing `index`. */
function alignBackward(buffer: Buffer, index: number): number {
  let cursor = index
  while (cursor > 0 && cursor < buffer.length && ((buffer[cursor] ?? 0) & 0xc0) === 0x80)
    cursor -= 1
  return cursor
}

/**
 * Split oversized input into UTF-8-aligned chunks. Every byte is scanned:
 * `maxScanBytes` bounds one regex run, not total coverage. Boundary windows let
 * the caller fall back to a single full-text pass when a multi-line or
 * provider-prefixed match straddles a chunk edge.
 */
function splitForScan(text: string, maxScanBytes: number): ScanSplit {
  const limit = Math.max(1, maxScanBytes)
  const buffer = Buffer.from(text, 'utf8')
  if (buffer.length <= limit) {
    return { chunks: [text], boundaryWindows: [], truncated: false }
  }

  const chunks: string[] = []
  const boundaryWindows: string[] = []
  let start = 0
  while (start < buffer.length) {
    const end = Math.min(alignForward(buffer, start + limit), buffer.length)
    chunks.push(buffer.subarray(start, end).toString('utf8'))
    if (end < buffer.length) {
      const overlapStart = alignBackward(buffer, Math.max(0, end - BOUNDARY_OVERLAP_BYTES))
      const overlapEnd = alignForward(buffer, Math.min(buffer.length, end + BOUNDARY_OVERLAP_BYTES))
      boundaryWindows.push(buffer.subarray(overlapStart, overlapEnd).toString('utf8'))
    }
    start = end
  }
  return { chunks, boundaryWindows, truncated: chunks.length > 1 }
}

/** Create a redactor bound to one config's limits and PII switch. */
export function createEngine(options: EngineOptions): Redactor {
  const maxScanBytes = Math.max(1, options.maxScanBytes)
  const activeCache = new Map<Level, readonly CompiledSecretRule[]>()

  const activeRules = (level: Level): readonly CompiledSecretRule[] => {
    const cached = activeCache.get(level)
    if (cached !== undefined) return cached
    const tier = maxTier(level)
    const rules = SECRET_RULES.filter(
      (rule) => rule.tier <= tier && (rule.pii !== true || options.piiEnabled),
    )
    activeCache.set(level, rules)
    return rules
  }

  const pseudonymizerFor = (rules: readonly CompiledSecretRule[]): Pseudonymizer | undefined =>
    rules.some((rule) => rule.pii === true) ? options.getPseudonymizer() : undefined

  /** Apply every active rule to one window, accumulating hits. */
  const redactWindow = (
    window: string,
    rules: readonly CompiledSecretRule[],
    pseudonymizer: Pseudonymizer | undefined,
    accumulator: HitAccumulator,
  ): string => {
    let current = window
    for (const rule of rules) {
      const replacement = replaceRule(current, rule, rule.pii === true ? pseudonymizer : undefined)
      if (replacement.matches === 0) continue
      current = replacement.text
      addHit(accumulator, rule.category, replacement.matches, rule.pii === true, replacement.ids)
    }
    return current
  }

  const redactTextCore = (
    text: string,
    rules: readonly CompiledSecretRule[],
    pseudonymizer: Pseudonymizer | undefined,
    accumulator: HitAccumulator,
  ): { text: string; truncated: boolean } => {
    const split = splitForScan(text, maxScanBytes)
    if (!split.truncated) {
      return { text: redactWindow(text, rules, pseudonymizer, accumulator), truncated: false }
    }
    // A match straddling a chunk edge is invisible to per-chunk rewrites. The
    // overlap windows are cheap; on a hit, redo the whole input in one pass so
    // the match is replaced instead of being duplicated or lost.
    if (split.boundaryWindows.some((window) => scanWindow(window, rules))) {
      return { text: redactWindow(text, rules, pseudonymizer, accumulator), truncated: true }
    }
    let output = ''
    for (const chunk of split.chunks) {
      output += redactWindow(chunk, rules, pseudonymizer, accumulator)
    }
    return { text: output, truncated: true }
  }

  const scan = (text: string, level: Level): boolean => {
    const rules = activeRules(level)
    if (rules.length === 0) return false
    const split = splitForScan(text, maxScanBytes)
    if (!split.truncated) return scanWindow(text, rules)
    for (const chunk of split.chunks) {
      if (scanWindow(chunk, rules)) return true
    }
    return split.boundaryWindows.some((window) => scanWindow(window, rules))
  }

  const redactText = (text: string, level: Level): TextRedaction => {
    const rules = activeRules(level)
    const pseudonymizer = pseudonymizerFor(rules)
    const accumulator: HitAccumulator = new Map()
    const outcome = redactTextCore(text, rules, pseudonymizer, accumulator)
    const result: TextRedaction = {
      text: outcome.text,
      changed: outcome.text !== text,
      hits: finalizeHits(accumulator),
    }
    if (outcome.truncated) result.truncated = true
    return result
  }

  const redactValue = (value: JsonValue, level: Level): ValueRedaction => {
    const rules = activeRules(level)
    const pseudonymizer = pseudonymizerFor(rules)
    const accumulator: HitAccumulator = new Map()
    let truncated = false

    const walk = (node: JsonValue): JsonValue => {
      if (typeof node === 'string') {
        const outcome = redactTextCore(node, rules, pseudonymizer, accumulator)
        if (outcome.truncated) truncated = true
        return outcome.text
      }
      if (Array.isArray(node)) {
        let changed = false
        const next = node.map((item) => {
          const walked = walk(item)
          if (walked !== item) changed = true
          return walked
        })
        return changed ? next : node
      }
      if (node !== null && typeof node === 'object') {
        let changed = false
        const entries = Object.entries(node).map(([key, child]) => {
          const walked = walk(child)
          if (walked !== child) changed = true
          return [key, walked] as const
        })
        if (!changed) return node
        const next: { [key: string]: JsonValue } = {}
        for (const [key, child] of entries) {
          // defineProperty keeps an own "__proto__" key a data property instead
          // of letting assignment mutate the rebuilt object's prototype.
          Object.defineProperty(next, key, {
            value: child,
            enumerable: true,
            configurable: true,
            writable: true,
          })
        }
        return next
      }
      return node
    }

    const nextValue = walk(value)
    const hits = finalizeHits(accumulator)
    const result: ValueRedaction = {
      value: nextValue,
      changed: nextValue !== value || hits.length > 0,
      hits,
    }
    if (truncated) result.truncated = true
    return result
  }

  const redactBlocks = (content: readonly BlockLike[], level: Level): ContentRedaction => {
    const rules = activeRules(level)
    const pseudonymizer = pseudonymizerFor(rules)
    const accumulator: HitAccumulator = new Map()
    let truncated = false
    let changed = false
    const next: BlockLike[] = []

    for (const block of content) {
      if (block.type !== 'text' || typeof block.text !== 'string') {
        next.push(block)
        continue
      }
      const outcome = redactTextCore(block.text, rules, pseudonymizer, accumulator)
      if (outcome.truncated) truncated = true
      if (outcome.text === block.text) {
        next.push(block)
        continue
      }
      changed = true
      next.push({ ...block, text: outcome.text })
    }

    const hits = finalizeHits(accumulator)
    if (!changed) {
      const unchanged: ContentRedaction = {
        content: content as unknown as BlockLike[],
        changed: false,
        hits,
      }
      if (truncated) unchanged.truncated = true
      return unchanged
    }
    const result: ContentRedaction = { content: next, changed: true, hits }
    if (truncated) result.truncated = true
    return result
  }

  return {
    scan,
    redactText,
    redactValue,
    redactBlocks,
    ruleCount: SECRET_RULES.length,
  }
}
