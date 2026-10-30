/**
 * False-positive filters for the redaction rule table.
 *
 * MIT License
 *
 * Copyright (c) 2026 jkt-check
 *
 * Derived from dsh-secret-scrub v0.1.2 (MIT, Copyright (c) 2026 jkt-check).
 * Modified by gythialy, 2026-10-19: converted to TypeScript for dsh-sensitive-guard;
 * placeholders and values are now supplied by the engine. The full MIT text is in
 * ./rules.ts and THIRD_PARTY_NOTICES.md.
 *
 * @module dsh-sensitive-guard/redact/filters
 */

/**
 * Luhn checksum over the digits of one credit-card candidate; the pattern's
 * single space/dash group separators are stripped first.
 */
export function luhnValid(candidate: string): boolean {
  const digits = candidate.replace(/[ -]/g, '')
  let sum = 0
  let double = false
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = digits.charCodeAt(index) - 48
    if (double) {
      digit *= 2
      if (digit > 9) digit -= 9
    }
    sum += digit
    double = !double
  }
  return sum % 10 === 0
}

/**
 * Env-var assignment names that hold no secret even though a keyword segment
 * makes them look sensitive.
 */
const SAFE_ENV_NAMES: ReadonlySet<string> = new Set([
  'PASSWORD_STORE_DIR', // pass(1) store location — a path, not a password
])

/**
 * Whether one `env-var-secret` match should be redacted. The pattern accepts
 * any uppercase assignment (keeping the regex linear), so this filter owns
 * both name checks: the name must carry a sensitive keyword as a whole
 * `_`-delimited segment — `AWS_SECRET_ACCESS_KEY` and `MY_API_KEY` are
 * secrets, `KEYBOARD`, `MONKEY`, `APIKEY`, and `KEYS` are not — and a
 * deny-listed safe name survives. The match keeps its full assignment shape
 * (`export NAME=value`), so the name is everything before the first `=`,
 * minus the `export` keyword.
 */
export function isSecretEnvAssignment(match: string): boolean {
  const assignment = match.trimStart().replace(/^export\s+/, '')
  const name = assignment.slice(0, assignment.indexOf('=')).trimEnd()
  if (!/(?:^|_)(?:KEY|SECRET|TOKEN|PASSWORD)(?:_|$)/.test(name)) return false
  return !SAFE_ENV_NAMES.has(name)
}

/**
 * Whether one `key-assignment` match should be redacted. The pattern accepts
 * any `name=value` shape (keeping the regex linear, like `env-var-secret`),
 * so this filter owns every semantic check:
 *
 * - the name must carry a sensitive keyword as a whole `_`-delimited segment
 *   (case-insensitive: `deepseek_api_key` and `MY_Token` are secrets,
 *   `monkey`, `keyboard`, and `apikey` are not);
 * - a deny-listed safe name survives (compared uppercase, so the lowercase
 *   form of `PASSWORD_STORE_DIR` is safe too);
 * - a PEM armor value (`PUBLIC_KEY=-----BEGIN …`) is not a secret;
 * - a dotted identifier chain value (`password=req.body.password`,
 *   `token=response.data.token`) is a code traversal, not a credential. The
 *   rejection only applies when EVERY `.`-separated segment is at most 20
 *   chars (identifier length): a longer tail is a random token, not a
 *   property path (`doppler_token=dp.pt.…` stays a secret). An
 *   `eyJ`-prefixed JWT value keeps its dots and stays a candidate;
 * - the value must mix at least two character classes with four or more
 *   distinct characters, and a pure-letter value must be at least 24 chars —
 *   shorter pure-letter values are usually identifiers (`token=computeToken()`),
 *   not credentials.
 */
export function isSensitiveKeyAssignment(match: string): boolean {
  const eq = match.indexOf('=')
  const name = match.slice(0, eq)
  if (!/(?:^|_)(?:key|secret|token|password)(?:_|$)/i.test(name)) return false
  if (SAFE_ENV_NAMES.has(name.toUpperCase())) return false
  const value = match.slice(eq + 1).replace(/^["']|["']$/g, '')
  if (value.startsWith('---')) return false
  if (
    !value.startsWith('eyJ') &&
    /^\$?[A-Za-z_][\w$]*(?:\.\$?[A-Za-z_][\w$]*)+$/.test(value) &&
    value.split('.').every((segment) => segment.length <= 20)
  ) {
    return false
  }
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((pattern) =>
    pattern.test(value),
  ).length
  if (classes < 2) return false
  if (new Set(value).size < 4) return false
  if (/^[A-Za-z]+$/.test(value) && value.length < 24) return false
  return true
}

/**
 * Substrings that mark a high-entropy candidate as a documentation
 * placeholder rather than a secret. `redacted` also covers fragments of the
 * scrubber's own placeholders, keeping a second pass idempotent.
 */
const FAKE_KEY_MARKERS = ['example', 'test', 'xxxx', 'your', 'placeholder', 'redacted']

/** Very common English words; two or more hits inside one run mark glued-together prose, not a token. */
const COMMON_WORDS = ['the', 'and', 'for', 'that', 'with', 'this', 'from']

/**
 * Bare hexadecimal digests and identifiers: git SHA-1 (40), MD5 (32), SHA-256
 * (64), and the 32-hex row/file ids CMS exports use. They carry no provider
 * prefix, are public identifiers rather than credentials, and the entropy
 * fallback is the only rule that would claim them — the documented git-SHA
 * false positive. Case-insensitive: digests appear in both cases.
 */
const PURE_HEX_ID = /^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/

/**
 * Post-filter for the `high-entropy` fallback; each rejection reason is
 * marked inline. Every check runs on the match alone, so a public-key PEM
 * body line (shareable by design) can still be redacted — the fallback is
 * the last resort and stays conservative.
 */
export function isHighEntropyToken(match: string): boolean {
  const lower = match.toLowerCase()
  // Documentation/example placeholders ('your_api_key_here' style).
  if (FAKE_KEY_MARKERS.some((marker) => lower.includes(marker))) return false
  // Bare hex digests and CMS/file row ids are identifiers, not credentials.
  if (PURE_HEX_ID.test(match)) return false
  // Character-class diversity: a real token mixes at least two of
  // lowercase / uppercase / digit / symbol; single-class runs are not secrets.
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((pattern) =>
    pattern.test(match),
  ).length
  if (classes < 2) return false
  // Distinct-character floor: kills low-entropy repeats that still mix two classes.
  if (new Set(match).size < 4) return false
  // Natural-language-ish: two or more common words in one run is prose.
  if (COMMON_WORDS.filter((word) => lower.includes(word)).length >= 2) return false
  return true
}

/**
 * Value fragments that mark an `api-key` assignment as a documentation
 * placeholder rather than a live credential (case-insensitive substring
 * match). The `<`/`>`/`${`/`}` markers can never appear in the pattern's
 * value class; they are kept for parity with the reference list.
 */
const FAKE_VALUE_MARKERS = [
  'xxx',
  '***',
  'your_',
  'your-',
  'your_key',
  'your-api-key',
  'test',
  'example',
  'placeholder',
  'changeme',
  'change_me',
  'redacted',
  'null',
  'none',
  'undefined',
  '<',
  '>',
  '${',
  '}',
]

/**
 * Whether one `api-key` match should be redacted: the value — everything
 * after the first `=` or `:`, quotes stripped — must not be an obvious
 * documentation placeholder.
 */
export function isRealApiKeyAssignment(match: string): boolean {
  const value = match
    .slice(match.search(/[=:]/) + 1)
    .trim()
    .replace(/^["']+|["']+$/g, '')
  const lower = value.toLowerCase()
  return !FAKE_VALUE_MARKERS.some((marker) => lower.includes(marker))
}
