/**
 * URL context for the redaction rule table: the character ranges covered by
 * the path section of absolute `http(s)` URLs. Path segments are document
 * identifiers (CMS row ids, file names, slugs), so the tier-2 entropy fallback
 * must not mistake them for credentials. Query strings and fragments are
 * deliberately excluded: signed URLs and OAuth callbacks carry their real
 * credentials there and stay fully covered.
 * @module dsh-sensitive-guard/redact/urls
 */

/** Half-open character range `[start, end)`. */
export type TextRange = readonly [start: number, end: number]

/**
 * One absolute `http(s)` URL. The character class excludes whitespace and the
 * quotes/angle brackets that terminate a URL in prose or markup, so every
 * match is one URL and the scan stays linear.
 */
const URL_PATTERN = /https?:\/\/[^\s<>"'`\\]+/gi

const SLASH = 0x2f
const QUESTION = 0x3f
const HASH = 0x23

/** Characters that end the authority section of a URL. */
function endsAuthority(code: number): boolean {
  return code === SLASH || code === QUESTION || code === HASH
}

/**
 * Path ranges of every absolute `http(s)` URL in one text window, sorted and
 * non-overlapping and ordered by start offset. The leading `/` is excluded and
 * a URL without a path (`https://host`, `https://host/`, `https://host?q=1`)
 * contributes no range.
 */
export function findUrlPathRanges(text: string): TextRange[] {
  if (!text.includes('://')) return []
  const pattern = new RegExp(URL_PATTERN.source, 'gi')
  const ranges: TextRange[] = []
  let match: RegExpExecArray | null
  while ((match = pattern.exec(text)) !== null) {
    const value = match[0]
    const scheme = value.indexOf('://')
    if (scheme < 0) continue
    let cursor = scheme + 3
    while (cursor < value.length && !endsAuthority(value.charCodeAt(cursor))) cursor += 1
    // The path starts at the first `/` after the authority; `?`/`#` or the end
    // of the match means this URL has none. The leading `/` is excluded so a
    // bare `https://host/` contributes no range at all.
    if (value.charCodeAt(cursor) !== SLASH) continue
    const start = cursor + 1
    let end = start
    while (end < value.length) {
      const code = value.charCodeAt(end)
      if (code === QUESTION || code === HASH) break
      end += 1
    }
    if (end > start) ranges.push([match.index + start, match.index + end])
  }
  return ranges
}

/**
 * Whether `[start, end)` is fully contained in one of the sorted,
 * non-overlapping ranges. A partial overlap is not containment: a match that
 * runs past a path boundary keeps its normal rule behaviour.
 */
export function containedInRanges(
  ranges: readonly TextRange[],
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
    else if (range[0] > start) high = middle - 1
    else return end <= range[1]
  }
  return false
}
