/**
 * Destination-level egress rules for the optional CONNECT guard. Matching is
 * string-only: the guard never resolves DNS, parses TLS, or inspects bodies, so
 * an entry names `host` or `host:port` and may use a glob in the host position.
 * @module dsh-sensitive-guard/egress/policy
 */
import picomatch from 'picomatch'

/** Destinations denied before any allow entry is consulted: cloud metadata. */
export const DEFAULT_EGRESS_DENY = ['169.254.169.254:80', 'metadata.google.internal'] as const

/** Stable machine-readable reasons, reused as the `X-Guard-Reason` code. */
export type EgressReason =
  | 'deny-list'
  | 'allow-list'
  | 'unknown-allow'
  | 'unknown-deny'
  | 'invalid-target'

/** One parsed destination. The host is lowercase and never carries brackets. */
export interface EgressTarget {
  host: string
  port: number
}

/** One decision for a destination; `ask` is impossible at this layer. */
export interface EgressDecision {
  action: 'allow' | 'deny'
  /** False when no entry matched and the configured unknown default applied. */
  matched: boolean
  reason: EgressReason
  /** Stable rule id such as `egress-deny[0]`; never the raw pattern. */
  rule?: string
}

/** One compiled entry: a host matcher plus an optional fixed port. */
export interface EgressRule {
  pattern: string
  host: string
  port?: number
  matches(target: EgressTarget): boolean
}

export interface EgressPolicyOptions {
  allow: readonly string[]
  deny: readonly string[]
  /** Decision for destinations that match no entry. */
  unknown: 'allow' | 'deny'
}

export interface EgressPolicy {
  evaluate(target: EgressTarget): EgressDecision
  readonly allowCount: number
  readonly denyCount: number
  readonly ruleCount: number
  readonly unknown: 'allow' | 'deny'
}

const HOST_REJECT = /[\s/@\\\p{Cc}]/u

function isPort(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 65535
}

/** Lowercase a host, drop a trailing root dot, and strip IPv6 brackets. */
export function normalizeEgressHost(raw: string): string | undefined {
  let value = raw.trim().toLowerCase()
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1)
  if (value.endsWith('.')) value = value.slice(0, -1)
  if (value.length === 0 || value.length > 255) return undefined
  if (HOST_REJECT.test(value)) return undefined
  return value
}

/**
 * Parse one `allow`/`deny` entry: `host`, `host:port`, `[v6]:port`, or a glob
 * such as `*.example.com`. Unparseable entries are dropped by compilation and
 * reported through the returned count, never silently matched.
 */
export function parseEgressEntry(raw: string): EgressRule | undefined {
  const entry = raw.trim()
  if (entry.length === 0) return undefined

  let hostPart = entry
  let portPart: string | undefined

  if (entry.startsWith('[')) {
    const close = entry.indexOf(']')
    if (close < 0) return undefined
    hostPart = entry.slice(0, close + 1)
    const rest = entry.slice(close + 1)
    if (rest.length > 0) {
      if (!rest.startsWith(':')) return undefined
      portPart = rest.slice(1)
    }
  } else {
    const colon = entry.lastIndexOf(':')
    if (colon > 0) {
      const candidate = entry.slice(colon + 1)
      if (candidate === '*' || /^\d{1,5}$/.test(candidate)) {
        hostPart = entry.slice(0, colon)
        portPart = candidate
      }
    }
    // An unbracketed IPv6 address is ambiguous with `host:port`; reject it.
    if (hostPart.includes(':')) return undefined
  }

  const host = normalizeEgressHost(hostPart)
  if (host === undefined) return undefined

  let port: number | undefined
  if (portPart !== undefined && portPart !== '*') {
    port = Number(portPart)
    if (!isPort(port)) return undefined
  }

  const glob = picomatch(host, { nocase: true, dot: true, contains: false })
  return {
    pattern: entry,
    host,
    ...(port === undefined ? {} : { port }),
    matches(target: EgressTarget): boolean {
      if (port !== undefined && target.port !== port) return false
      return glob(target.host)
    },
  }
}

/**
 * Parse a CONNECT authority (`host:port`) or a bare host. CONNECT always
 * carries a port, so a missing one yields `undefined` rather than a guess.
 */
export function parseEgressAuthority(raw: string): EgressTarget | undefined {
  const value = raw.trim()
  if (value.length === 0) return undefined

  if (value.startsWith('[')) {
    const close = value.indexOf(']')
    if (close < 0) return undefined
    const host = normalizeEgressHost(value.slice(0, close + 1))
    const rest = value.slice(close + 1)
    if (host === undefined || !rest.startsWith(':')) return undefined
    const port = Number(rest.slice(1))
    if (!isPort(port)) return undefined
    return { host, port }
  }

  const colon = value.lastIndexOf(':')
  if (colon <= 0) return undefined
  const hostPart = value.slice(0, colon)
  // IPv6 must be bracketed: a bare `a:b:c` cannot be read as host and port.
  if (hostPart.includes(':')) return undefined
  const host = normalizeEgressHost(hostPart)
  const port = Number(value.slice(colon + 1))
  if (host === undefined || !isPort(port)) return undefined
  return { host, port }
}

function compile(entries: readonly string[]): EgressRule[] {
  const rules: EgressRule[] = []
  for (const entry of entries) {
    const rule = parseEgressEntry(entry)
    if (rule !== undefined) rules.push(rule)
  }
  return rules
}

/**
 * Compile entries once at mount. Deny entries win over allow entries, which
 * keeps a broad allow glob from silently re-admitting a denied destination.
 */
export function createEgressPolicy(options: EgressPolicyOptions): EgressPolicy {
  const allow = compile(options.allow)
  const deny = compile(options.deny)

  return {
    unknown: options.unknown,
    allowCount: allow.length,
    denyCount: deny.length,
    ruleCount: allow.length + deny.length,
    evaluate(target: EgressTarget): EgressDecision {
      if (!isPort(target.port)) {
        return { action: 'deny', matched: false, reason: 'invalid-target' }
      }
      const host = normalizeEgressHost(target.host)
      if (host === undefined) {
        return { action: 'deny', matched: false, reason: 'invalid-target' }
      }
      const normalized: EgressTarget = { host, port: target.port }

      for (const [index, rule] of deny.entries()) {
        if (rule.matches(normalized)) {
          return {
            action: 'deny',
            matched: true,
            reason: 'deny-list',
            rule: 'egress-deny[' + index + ']',
          }
        }
      }
      for (const [index, rule] of allow.entries()) {
        if (rule.matches(normalized)) {
          return {
            action: 'allow',
            matched: true,
            reason: 'allow-list',
            rule: 'egress-allow[' + index + ']',
          }
        }
      }
      return options.unknown === 'deny'
        ? { action: 'deny', matched: false, reason: 'unknown-deny' }
        : { action: 'allow', matched: false, reason: 'unknown-allow' }
    },
  }
}
