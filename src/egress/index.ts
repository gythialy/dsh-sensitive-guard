/**
 * Lifecycle for the optional egress guard: bind the loopback listener, prove
 * the wiring, record decisions, and expose a count-only view to `/guard egress`.
 * The listener fills DSH's existing `HTTPS_PROXY` seam; it is not a sandbox and
 * never inspects content.
 * @module dsh-sensitive-guard/egress
 */
import type { AuditLog, EgressRecord } from '../audit.js'
import type { GuardConfig } from '../config.js'
import type { GuardMode, Logger } from '../contracts.js'
import { runEgressCanary, type CanaryResult } from './canary.js'
import { createEgressPolicy } from './policy.js'
import { startEgressServer, type EgressServer } from './server.js'

/** The loopback address the guard always binds; never a wildcard. */
export const EGRESS_HOST = '127.0.0.1'

/** How many recent destinations `/guard egress status` keeps for display. */
const RECENT_LIMIT = 5

export interface EgressCounts {
  tunnels: number
  allowed: number
  denied: number
  bytesIn: number
  bytesOut: number
}

/** One recent destination, host and port only. */
export interface EgressRecent {
  host: string
  port: number
  decision: 'allow' | 'deny'
  enforced: boolean
  reason: string
}

export interface EgressSnapshot {
  enabled: true
  bound: boolean
  host: string
  port: number
  mode: GuardMode
  unknown: 'allow' | 'deny'
  failClosed: boolean
  allowRules: number
  denyRules: number
  upstream?: string
  /** Sanitized proxy value this process was launched with, if any. */
  proxyEnv?: string
  /** True when that value names this listener's host and port. */
  envMatches: boolean
  counts: EgressCounts
  recent: EgressRecent[]
  lastCanary?: CanaryResult
}

export interface EgressController {
  readonly port: number
  readonly bound: boolean
  snapshot(): EgressSnapshot
  canary(): Promise<CanaryResult>
  close(): Promise<void>
}

export interface EgressMountOptions {
  config: GuardConfig['egress']
  modeOf: () => GuardMode
  audit: AuditLog
  logger: Logger
  /** Injectable environment for tests. */
  env?: NodeJS.ProcessEnv
}

/**
 * Read the HTTPS proxy value DSH resolved for this process. Lowercase wins, as
 * in `@deepseek-ai/dsh-http-proxy`; a blank value counts as unset.
 */
export function resolveProxyEnv(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const raw = env.https_proxy ?? env.HTTPS_PROXY
  if (raw === undefined) return undefined
  const value = raw.trim()
  return value.length === 0 ? undefined : value
}

/** Strip userinfo before a proxy value reaches a log or the model contract. */
export function sanitizeProxyValue(value: string): string {
  try {
    const url = new URL(value)
    return url.protocol + '//' + url.host
  } catch {
    return '(invalid proxy value)'
  }
}

/** True when a proxy value points at the loopback listener on this port. */
export function proxyEnvMatches(value: string | undefined, port: number): boolean {
  if (value === undefined) return false
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return false
  }
  if (url.protocol !== 'http:') return false
  if (url.username.length > 0 || url.password.length > 0) return false
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') return false
  const effective = url.port.length === 0 ? 80 : Number(url.port)
  return effective === port
}

/**
 * Mount the guard. Rejects when the listener cannot bind and `failClosed` is
 * on, which turns a misconfigured port into a failed plugin instead of silent
 * no coverage. The returned controller's disposer closes the listener.
 */
export async function mountEgress(options: EgressMountOptions): Promise<EgressController> {
  const settings = options.config
  const env = options.env ?? process.env
  const port = settings.port
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(
      'Sensitive Guard: egress.port must be an integer between 1 and 65535 (got ' +
        String(port) +
        ').',
    )
  }

  const policy = createEgressPolicy({
    allow: settings.allow,
    deny: settings.deny,
    unknown: settings.unknown,
  })
  const counts: EgressCounts = { tunnels: 0, allowed: 0, denied: 0, bytesIn: 0, bytesOut: 0 }
  const recent: EgressRecent[] = []

  const record = (entry: EgressRecord): void => {
    options.audit.egress(entry)
    if (entry.event === 'connect') {
      counts.tunnels += 1
      if (entry.decision === 'allow') counts.allowed += 1
    }
    if (entry.enforced === true) counts.denied += 1
    if (entry.bytesIn !== undefined) counts.bytesIn += entry.bytesIn
    if (entry.bytesOut !== undefined) counts.bytesOut += entry.bytesOut
    if (
      entry.event === 'connect' &&
      entry.host !== undefined &&
      entry.port !== undefined &&
      entry.decision !== undefined
    ) {
      recent.push({
        host: entry.host,
        port: entry.port,
        decision: entry.decision,
        enforced: entry.enforced === true,
        reason: entry.reason ?? 'unknown',
      })
      while (recent.length > RECENT_LIMIT) recent.shift()
    }
  }

  const modeOf = options.modeOf
  let server: EgressServer | undefined
  try {
    server = await startEgressServer({
      port,
      host: EGRESS_HOST,
      policy,
      mode: modeOf,
      record,
      logger: options.logger,
      ...(settings.upstream.trim().length === 0 ? {} : { upstream: settings.upstream.trim() }),
    })
  } catch (error) {
    record({ event: 'error', port, mode: modeOf(), reason: 'bind-failed', outcome: 'error' })
    if (settings.failClosed) {
      throw new Error(
        'Sensitive Guard: the egress guard could not bind ' +
          EGRESS_HOST +
          ':' +
          String(port) +
          '. Free the port or set egress.failClosed: false to start without egress coverage.',
        { cause: error },
      )
    }
    options.logger.warn(
      'Sensitive Guard: the egress guard could not bind ' +
        EGRESS_HOST +
        ':' +
        String(port) +
        ' — egress coverage is unavailable.',
    )
  }

  const envMatchesNow = (): boolean =>
    server !== undefined && proxyEnvMatches(resolveProxyEnv(env), server.port)
  const proxyEnv = resolveProxyEnv(env)

  record({
    event: 'mount',
    port: server === undefined ? port : server.port,
    mode: modeOf(),
    reason: envMatchesNow() ? 'env-ok' : proxyEnv === undefined ? 'env-missing' : 'env-mismatch',
  })

  if (server !== undefined && !envMatchesNow()) {
    options.logger.warn(
      'Sensitive Guard: the egress listener is bound on ' +
        EGRESS_HOST +
        ':' +
        String(server.port) +
        ' but https_proxy does not point at it (' +
        (proxyEnv === undefined ? 'unset' : sanitizeProxyValue(proxyEnv)) +
        '). Launched clients are not covered until the environment names this port — see /guard egress status.',
    )
  }

  let lastCanary: CanaryResult | undefined
  if (server !== undefined && settings.canary) {
    lastCanary = await runEgressCanary(server.port, { host: EGRESS_HOST })
    record({
      event: 'canary',
      port: server.port,
      mode: modeOf(),
      reason: lastCanary.code,
      outcome: lastCanary.ok ? 'ok' : 'error',
      ...(lastCanary.status === undefined ? {} : { status: lastCanary.status }),
    })
    if (!lastCanary.ok) {
      options.logger.warn(
        'Sensitive Guard: the egress canary failed (' +
          lastCanary.code +
          ') on ' +
          EGRESS_HOST +
          ':' +
          String(server.port) +
          '.',
      )
    }
  }

  return {
    get port(): number {
      return server === undefined ? port : server.port
    },
    get bound(): boolean {
      return server !== undefined
    },
    snapshot(): EgressSnapshot {
      return {
        enabled: true,
        bound: server !== undefined,
        host: EGRESS_HOST,
        port: server === undefined ? port : server.port,
        mode: modeOf(),
        unknown: settings.unknown,
        failClosed: settings.failClosed,
        allowRules: policy.allowCount,
        denyRules: policy.denyCount,
        ...(settings.upstream.trim().length === 0
          ? {}
          : { upstream: sanitizeProxyValue(settings.upstream.trim()) }),
        ...(proxyEnv === undefined ? {} : { proxyEnv: sanitizeProxyValue(proxyEnv) }),
        envMatches: envMatchesNow(),
        counts: { ...counts },
        recent: [...recent],
        ...(lastCanary === undefined ? {} : { lastCanary }),
      }
    },
    async canary(): Promise<CanaryResult> {
      if (server === undefined) return { ok: false, code: 'refused', latencyMs: 0 }
      const result = await runEgressCanary(server.port, { host: EGRESS_HOST })
      lastCanary = result
      record({
        event: 'canary',
        port: server.port,
        mode: modeOf(),
        reason: result.code,
        outcome: result.ok ? 'ok' : 'error',
        ...(result.status === undefined ? {} : { status: result.status }),
      })
      return result
    },
    async close(): Promise<void> {
      await server?.close()
    },
  }
}
