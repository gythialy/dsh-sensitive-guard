/**
 * Secret and PII rule table, adapted from dsh-secret-scrub v0.1.2.
 *
 * MIT License
 *
 * Copyright (c) 2026 jkt-check
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Derived from dsh-secret-scrub v0.1.2 (MIT, Copyright (c) 2026 jkt-check).
 * Modified by gythialy, 2026-10-19: converted to TypeScript for dsh-sensitive-guard; placeholders and values are now supplied by the engine.
 *
 * @module dsh-sensitive-guard/redact/rules
 */
import type { Level } from '../contracts.js'
import {
  isHighEntropyToken,
  isRealApiKeyAssignment,
  isSecretEnvAssignment,
  isSensitiveKeyAssignment,
  luhnValid,
} from './filters.js'

/** Rule tier: 0 = core credentials, 1 = assignments, 2 = PII and fallbacks. */
export type RuleTier = 0 | 1 | 2

/** Post-match validator; returning false keeps the original text uncounted. */
export type RuleValidator = (match: string) => boolean

/** One compiled rule. Patterns are global and shared; callers must reset lastIndex. */
export interface CompiledSecretRule {
  readonly category: string
  readonly tier: RuleTier
  readonly pattern: RegExp
  readonly validate?: RuleValidator
  /** PII rules emit keyed `[[PII_...]]` pseudonyms instead of secret placeholders. */
  readonly pii?: boolean
}

/** Categories that use keyed PII pseudonyms instead of random secret ids. */
export const PII_CATEGORIES: ReadonlySet<string> = new Set([
  'email',
  'phone-cn',
  'phone-intl',
  'id-cn',
  'credit-card',
  'ssn-us',
])

/**
 * Built-in rules, all global-flagged, ordered by tier ascending and, within
 * a tier, from most specific to most general. Tiers 0–1 are prefix-anchored
 * (provider key prefixes, assignment shapes, URL authority forms); tier 2
 * matches shapes (PII and high-entropy runs). The ordering lets broad
 * multi-line and provider-prefixed rules claim their spans before the generic
 * fallbacks (`generic-sk-key`, `generic-bearer`, `high-entropy`) run.
 * `private-key` spans lines and runs first so nothing else claims pieces of a
 * PEM body; `id-cn` runs before `credit-card` so a Luhn-valid 17–19 digit
 * run categorizes as the more specific PII id; `generic-bearer` and
 * `high-entropy` are the per-tier fallbacks.
 */
export const SECRET_RULES: readonly CompiledSecretRule[] = Object.freeze([
  {
    category: 'private-key',
    tier: 0,
    pattern:
      /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
  },
  {
    category: 'private-key-truncated',
    tier: 0,
    // Truncation remnants, claimed immediately after complete blocks: an
    // unclosed BEGIN redacts through the end of the text (tail truncation),
    // an orphaned END redacts from the start of the text through the marker
    // (head truncation). Both present yields placeholder + middle slice +
    // placeholder. A lone BEGIN quoted in documentation over-redacts the
    // rest of the text — accepted, privacy-first.
    //
    // The two truncation directions are separate same-category rules instead
    // of one alternation: a single regex with one-sided ^/$ anchors is parsed
    // as (^head)|(tail$) and CodeQL reports js/regex/missing-regexp-anchor.
    // Keeping each branch anchored is also what bounds the scan: an
    // unanchored [\s\S]*? would backtrack quadratically on large inputs.
    pattern: /^[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
  },
  {
    category: 'private-key-truncated',
    tier: 0,
    // Tail truncation: an unclosed BEGIN redacts through the end of the text.
    // Anchoring at $ keeps the greedy tail linear and makes the intent clear.
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*$/g,
  },
  {
    category: 'api-key',
    tier: 0,
    // Generic `apikey` assignment: the fixed name `api` + optional `_`/`-`
    // + `key` in any case, `=` or `:` separator with optional surrounding
    // whitespace and quotes (JSON form `"api_key": "…"`), value of 8+ token
    // characters. No leading `\b`: the span inside a longer name
    // (`deepseek_api_key=…`) is claimed here at tier 0. The value class
    // includes `.` so a three-segment JWT is consumed whole. The closing quote
    // is deliberately NOT consumed so the JSON form stays parseable.
    pattern: /[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]['"]?\s*[=:]\s*['"]?[A-Za-z0-9_+\-/.]{8,}/g,
    validate: isRealApiKeyAssignment,
  },
  { category: 'aws-access-key', tier: 0, pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  {
    category: 'github-token',
    tier: 0,
    pattern: /(?:\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{22,})/g,
  },
  { category: 'google-api-key', tier: 0, pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  // `sk-` + exactly 32 lowercase hex (DeepSeek).
  { category: 'deepseek-key', tier: 0, pattern: /\bsk-[0-9a-f]{32}\b/g },
  {
    category: 'openai-key',
    tier: 0,
    pattern: /(?:\bsk-proj-[A-Za-z0-9_-]{20,}\b|\bsk-[A-Za-z0-9]{48}\b)/g,
  },
  { category: 'anthropic-key', tier: 0, pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g },
  { category: 'gitlab-pat', tier: 0, pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  // Rollbar's exact-32 shape runs before stripe-key's looser
  // `[sr]k_(live|test)_…{16,}` so a real rollbar token keeps its category.
  { category: 'rollbar-token', tier: 0, pattern: /\brk_(?:live|test)_[A-Za-z0-9]{32}\b/g },
  { category: 'stripe-key', tier: 0, pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  {
    category: 'slack-token',
    tier: 0,
    pattern: /(?:\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bxapp-[A-Za-z0-9-]{10,}\b)/g,
  },
  { category: 'slack-signing-secret', tier: 0, pattern: /\bwhsec_[A-Za-z0-9]{32,}\b/g },
  // No scheme requirement: a scheme-less paste is still a live credential.
  {
    category: 'slack-webhook-url',
    tier: 0,
    pattern: /hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9+/]{43,46}/g,
  },
  { category: 'npm-token', tier: 0, pattern: /\bnpm_[A-Za-z0-9]{36}\b/g },
  // The fixed macaroon prefix keeps the rule from matching prose mentions.
  { category: 'pypi-token', tier: 0, pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g },
  { category: 'sendgrid-key', tier: 0, pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { category: 'twilio-key', tier: 0, pattern: /\bSK[0-9a-f]{32}\b/g },
  { category: 'digitalocean-token', tier: 0, pattern: /\bdop_v1_[0-9a-f]{64}\b/g },
  { category: 'shopify-token', tier: 0, pattern: /\bshpat_[0-9a-f]{32}\b/g },
  { category: 'telegram-bot-token', tier: 0, pattern: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g },
  { category: 'tavily-key', tier: 0, pattern: /\btvly-[A-Za-z0-9_-]{20,}\b/g },
  // Fixed prefix + exact 58-char bech32 charset is the guard; no `\b`.
  {
    category: 'age-secret-key',
    tier: 0,
    pattern: /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/g,
  },
  { category: 'docker-pat', tier: 0, pattern: /\bdckr_pat_[A-Za-z0-9_-]{27}\b/g },
  { category: 'notion-token', tier: 0, pattern: /\bntn_[0-9]{11}[A-Za-z0-9]{32}\b/g },
  { category: 'supabase-token', tier: 0, pattern: /\bsbp_[a-f0-9]{40}\b/g },
  { category: 'linear-api-key', tier: 0, pattern: /\blin_api_[A-Za-z0-9]{40}\b/g },
  // Generic `sk-`/`sk_` fallback: runs after every provider-specific sk rule.
  { category: 'generic-sk-key', tier: 0, pattern: /\bsk[-_][A-Za-z0-9_-]{20,}\b/g },
  // Connection-URL authority: the whole `scheme://user:password@` span is
  // replaced, leaving the host readable after the placeholder. The userinfo
  // classes exclude brackets so a placeholder emitted earlier is never
  // re-consumed.
  {
    category: 'url-credentials',
    tier: 0,
    pattern:
      /(?:mysql|postgres|postgresql|mongodb|redis|amqp|rabbitmq|sftp|smtp):\/\/[^:\s[\]]*:[^@\s[\]]+@/gi,
  },
  // OAuth callback query token: the whole `?access_token=<value>` span is
  // replaced, including the parameter name.
  {
    category: 'url-access-token',
    tier: 0,
    pattern: /[?&][Aa]ccess_[Tt]oken=[A-Za-z0-9._~+/=-]{8,}/g,
  },
  {
    category: 'generic-bearer',
    tier: 0,
    pattern:
      /(?:\bBearer [A-Za-z0-9._~+/=-]{16,}|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/g,
  },
  {
    category: 'env-var-secret',
    tier: 1,
    // Assignment-shaped secrets: any uppercase `NAME=value` (with optional
    // `export`) matches, and the validate filter keeps only names carrying a
    // sensitive keyword as a whole `_`-delimited segment. Horizontal
    // whitespace only (`[^\S\n]`): a match never starts on an earlier blank
    // line and never spans a newline around `=`.
    pattern:
      /^[^\S\n]*(?:export[^\S\n]+)?[A-Z0-9_]+[^\S\n]*=[^\S\n]*(?:(?:[^\s'"]+|"[^"]*"|'[^']*')+|"[^"\n]*|'[^'\n]*)/gm,
    validate: isSecretEnvAssignment,
  },
  {
    category: 'azure-storage-key',
    tier: 1,
    pattern: /[Aa]ccount[Kk]ey=["']?[A-Za-z0-9+/=]{86,88}["']?/g,
  },
  { category: 'alibaba-access-key', tier: 1, pattern: /\bLTAI[A-Za-z0-9]{16,}\b/g },
  {
    category: 'key-assignment',
    tier: 1,
    // Assignment-shaped secrets in ANY case: the lowercase and mixed-case
    // shapes `env-var-secret` cannot see (`deepseek_api_key=…`,
    // `MY_Token=…`). The pattern accepts every `name=value` shape and the
    // validate filter owns the semantics. `=` must follow the name
    // immediately (no whitespace), so code like `token = 5` never matches.
    pattern: /\b[A-Za-z0-9_]+=(?:"[^"\n]{8,}"|'[^'\n]{8,}'|[A-Za-z0-9_\-+/=.]{8,})/g,
    validate: isSensitiveKeyAssignment,
  },
  {
    // Bounded quantifiers keep mismatch on long `@`-less runs linear.
    category: 'email',
    tier: 2,
    pii: true,
    pattern: /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b/g,
  },
  { category: 'phone-cn', tier: 2, pii: true, pattern: /(?<!\d)1[3-9]\d{9}(?!\d)/g },
  // E.164 with a leading `+`: the plus keeps it disjoint from `phone-cn`
  // and `id-cn`, and the trailing boundary rejects longer digit runs.
  { category: 'phone-intl', tier: 2, pii: true, pattern: /\+[1-9]\d{7,14}\b/g },
  // Chinese resident id (GB 11643-1999): 17–19 digits plus the optional X/x
  // checksum letter; no checksum validation — a plausible shape is redacted.
  { category: 'id-cn', tier: 2, pii: true, pattern: /(?<!\d)\d{17,19}[Xx]?(?!\d)/g },
  {
    category: 'credit-card',
    tier: 2,
    pii: true,
    // The final digit carries no separator, so a trailing space or dash is
    // never consumed.
    pattern: /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,
    validate: luhnValid,
  },
  { category: 'ssn-us', tier: 2, pii: true, pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  {
    category: 'high-entropy',
    tier: 2,
    pattern: /\b[A-Za-z0-9+=]{20,}\b/g,
    validate: isHighEntropyToken,
  },
])

/** The highest active tier for one level. */
const MAX_TIER: Readonly<Record<Level, RuleTier>> = {
  minimal: 0,
  balanced: 1,
  aggressive: 2,
}

/** Map a configured level to its highest active tier. */
export function maxTier(level: Level): RuleTier {
  return MAX_TIER[level] ?? 0
}
