/**
 * Glob compilation with fixed resource bounds. Patterns are compiled once at
 * rule-load time; evaluation only calls prepared matchers.
 * @module dsh-sensitive-guard/policy/glob
 */
import picomatch from 'picomatch'
import type { Matcher } from './types.js'

/** Longest accepted pattern; mirrors the vendored baseline's glob cap. */
export const MAX_GLOB_PATTERN_LENGTH = 512

export interface GlobOptions {
  platform: NodeJS.Platform
}

/**
 * Escape picomatch syntax that shell signatures use literally. Bare `(`, `)`,
 * and `|` are extglob/alternation operators to picomatch: an unbalanced `(`
 * degrades to the never-matching `/$^/`, and `|` silently widens a pattern.
 * The fork-bomb signature and the `curl*|*sh` pipeline rule both need those
 * characters literal, so this guard intentionally supports only `*`, `?`,
 * character classes, and brace expansion — not extglob/alternation.
 *
 * Already-escaped characters and backslash escapes are preserved.
 */
export function escapeLiteralGlobSyntax(pattern: string): string {
  let output = ''
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index]!
    if (char === '\\') {
      output += char
      const next = pattern[index + 1]
      if (next !== undefined) {
        output += next
        index += 1
      }
      continue
    }
    output += char === '(' || char === ')' || char === '|' ? '\\' + char : char
  }
  return output
}

/**
 * Compile one glob. `dot: true` lets dotfiles match path globs, `nonegate`
 * keeps a leading `!` literal (argv negation is handled by the loader), and
 * `nocase` makes Windows matching case-insensitive.
 */
export function compileGlob(pattern: string, options: GlobOptions): Matcher {
  if (typeof pattern !== 'string' || pattern.length === 0) {
    throw new Error('sensitive-guard: empty glob pattern in rule match')
  }
  if (pattern.length > MAX_GLOB_PATTERN_LENGTH) {
    throw new Error(`sensitive-guard: glob pattern exceeds ${MAX_GLOB_PATTERN_LENGTH} characters`)
  }
  return picomatch(escapeLiteralGlobSyntax(pattern), {
    dot: true,
    nocase: options.platform === 'win32',
    nonegate: true,
  })
}

/** Compile every pattern, preserving order for diagnostics. */
export function compileGlobs(patterns: readonly string[], options: GlobOptions): Matcher[] {
  return patterns.map((pattern) => compileGlob(pattern, options))
}

/** True when at least one compiled matcher accepts the input. */
export function matchesAny(matchers: readonly Matcher[], input: string): boolean {
  for (const matcher of matchers) {
    if (matcher(input)) return true
  }
  return false
}
