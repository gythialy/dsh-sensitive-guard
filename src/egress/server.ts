/**
 * Loopback CONNECT tunnel and plain-HTTP forward proxy. This is the endpoint
 * DSH's launcher already routes through `HTTPS_PROXY`; decisions cover the
 * destination host and port only, so no certificate authority is involved and
 * no body is ever inspected here.
 * @module dsh-sensitive-guard/egress/server
 */
import {
  createServer as createHttpServer,
  request as httpRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type OutgoingHttpHeaders,
  type ServerResponse,
} from 'node:http'
import { connect as netConnect, type Socket } from 'node:net'
import type { EgressRecord } from '../audit.js'
import type { GuardMode, Logger } from '../contracts.js'
import {
  normalizeEgressHost,
  parseEgressAuthority,
  type EgressPolicy,
  type EgressTarget,
} from './policy.js'

const CONNECT_TIMEOUT_MS = 15_000
const IDLE_TIMEOUT_MS = 300_000
const MAX_UPSTREAM_HEADER_BYTES = 64 * 1024

/** Hop-by-hop headers are never forwarded across a proxy hop. */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

export interface EgressServerOptions {
  /** Loopback port; `0` asks the kernel for one (tests only). */
  port: number
  host?: string
  policy: EgressPolicy
  mode: () => GuardMode
  record: (record: EgressRecord) => void
  logger?: Logger
  /** Optional upstream HTTP proxy to chain CONNECT tunnels through. */
  upstream?: string
  connectTimeoutMs?: number
  idleTimeoutMs?: number
}

export interface EgressServer {
  readonly port: number
  close(): Promise<void>
}

interface Tunnel {
  socket: Socket
  /** Bytes the chained upstream sent after its CONNECT response headers. */
  leftover?: Buffer
}

function safeToken(value: string): string {
  return value
    .replace(/[\p{Cc}"\\]/gu, '')
    .trim()
    .slice(0, 64)
}

/** Model-visible code explaining a refusal; the caller sees `fetch failed`. */
export function guardHeaderCode(reason: string): string {
  switch (reason) {
    case 'deny-list':
      return 'denied-by-rule'
    case 'unknown-deny':
      return 'unknown-destination-blocked'
    case 'invalid-target':
      return 'invalid-target'
    case 'upstream-failure':
      return 'upstream-failure'
    default:
      return 'denied'
  }
}

function writeTunnelDeny(
  socket: Socket,
  reason: string,
  rule?: string,
  status = '403 Forbidden',
): void {
  const lines = [
    'HTTP/1.1 ' + status,
    'Content-Length: 0',
    'Connection: close',
    'X-Guard-Reason: ' + safeToken(guardHeaderCode(reason)),
  ]
  if (rule !== undefined) lines.push('X-Guard-Rule: ' + safeToken(rule))
  socket.on('error', () => socket.destroy())
  socket.end(lines.join('\r\n') + '\r\n\r\n')
}

function writeHttpDeny(response: ServerResponse, reason: string, rule?: string, code = 403): void {
  const headers: OutgoingHttpHeaders = {
    'content-length': '0',
    'x-guard-reason': safeToken(guardHeaderCode(reason)),
  }
  if (rule !== undefined) headers['x-guard-rule'] = safeToken(rule)
  response.writeHead(code, headers)
  response.end()
}

/** RFC 9110 token characters; anything else is not a header name. */
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/

/**
 * Response headers a forward proxy mirrors. The list is deliberately constant:
 * a header name taken from the upstream response never becomes an object key.
 */
const FORWARDED_RESPONSE_HEADERS = [
  'accept-ranges',
  'cache-control',
  'content-disposition',
  'content-encoding',
  'content-language',
  'content-length',
  'content-range',
  'content-type',
  'etag',
  'expires',
  'last-modified',
  'location',
  'retry-after',
  'set-cookie',
  'vary',
] as const

/**
 * Request headers are forwarded as-is (tool auth lives in custom headers), so
 * they are validated as tokens and assembled without a computed-key write.
 */
function forwardRequestHeaders(headers: IncomingHttpHeaders): OutgoingHttpHeaders {
  const entries: Array<[string, string | string[]]> = []
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue
    if (HOP_BY_HOP.has(name.toLowerCase()) || !HEADER_NAME.test(name)) continue
    entries.push([name, value])
  }
  return Object.fromEntries(entries) as OutgoingHttpHeaders
}

interface ParsedHttpRequest {
  target: EgressTarget
  path: string
}

/** Resolve the destination of a plain-HTTP proxy request without any I/O. */
export function parseHttpTarget(request: IncomingMessage): ParsedHttpRequest | undefined {
  const raw = request.url ?? ''
  let url: URL | undefined
  try {
    url = new URL(raw)
  } catch {
    url = undefined
  }
  if (url === undefined) {
    const hostHeader = request.headers.host
    if (hostHeader === undefined) return undefined
    const path = raw.startsWith('/') ? raw : '/' + raw
    try {
      url = new URL('http://' + hostHeader + path)
    } catch {
      return undefined
    }
  }
  if (url.protocol !== 'http:') return undefined
  if (url.username.length > 0 || url.password.length > 0) return undefined
  const host = normalizeEgressHost(url.hostname)
  if (host === undefined) return undefined
  const port = url.port.length === 0 ? 80 : Number(url.port)
  if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined
  return { target: { host, port }, path: url.pathname + url.search }
}

function parseUpstream(raw: string): EgressTarget | undefined {
  try {
    const url = new URL(raw)
    if (url.protocol !== 'http:') return undefined
    if (url.username.length > 0 || url.password.length > 0) return undefined
    const host = normalizeEgressHost(url.hostname)
    if (host === undefined) return undefined
    const port = url.port.length === 0 ? 80 : Number(url.port)
    if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined
    return { host, port }
  } catch {
    return undefined
  }
}

/**
 * A request aimed at the listener itself would forward into the guard, so it is
 * refused as invalid instead of recursing.
 */
function isSelfTarget(target: EgressTarget, boundPort: number): boolean {
  if (target.port !== boundPort) return false
  return target.host === '127.0.0.1' || target.host === 'localhost' || target.host === '::1'
}

function authorityOf(target: EgressTarget): string {
  const host = target.host.includes(':') ? '[' + target.host + ']' : target.host
  return host + ':' + String(target.port)
}

function directTunnel(target: EgressTarget, timeoutMs: number): Promise<Tunnel> {
  return new Promise<Tunnel>((resolve, reject) => {
    const socket = netConnect({ host: target.host, port: target.port })
    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error('connect-timeout'))
    }, timeoutMs)
    socket.once('connect', () => {
      clearTimeout(timer)
      socket.setNoDelay(true)
      resolve({ socket })
    })
    socket.once('error', (error: Error) => {
      clearTimeout(timer)
      reject(error)
    })
  })
}

/** Chain a CONNECT tunnel through an upstream proxy and keep its surplus bytes. */
function chainedTunnel(
  target: EgressTarget,
  upstream: EgressTarget,
  timeoutMs: number,
): Promise<Tunnel> {
  return new Promise<Tunnel>((resolve, reject) => {
    const socket = netConnect({ host: upstream.host, port: upstream.port })
    let settled = false
    let buffer = Buffer.alloc(0)

    const fail = (error: Error): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      reject(error)
    }

    const timer = setTimeout(() => fail(new Error('upstream-timeout')), timeoutMs)

    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk])
      const end = buffer.indexOf('\r\n\r\n')
      if (end < 0) {
        if (buffer.length > MAX_UPSTREAM_HEADER_BYTES) fail(new Error('upstream-header-too-large'))
        return
      }
      socket.off('data', onData)
      const head = buffer.subarray(0, end).toString('latin1')
      const rest = buffer.subarray(end + 4)
      const status = Number.parseInt(head.split(' ')[1] ?? '', 10)
      if (status !== 200) {
        fail(new Error('upstream-status-' + (Number.isNaN(status) ? 'unknown' : String(status))))
        return
      }
      settled = true
      clearTimeout(timer)
      socket.setNoDelay(true)
      resolve(rest.length > 0 ? { socket, leftover: Buffer.from(rest) } : { socket })
    }

    socket.once('connect', () => {
      socket.setNoDelay(true)
      const authority = authorityOf(target)
      socket.write('CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n\r\n')
    })
    socket.on('data', onData)
    socket.once('error', fail)
    socket.once('close', () => fail(new Error('upstream-closed')))
  })
}

function openTunnel(
  target: EgressTarget,
  options: EgressServerOptions,
  timeoutMs: number,
): Promise<Tunnel> {
  const raw = options.upstream
  if (raw === undefined || raw.trim().length === 0) return directTunnel(target, timeoutMs)
  const upstream = parseUpstream(raw)
  if (upstream === undefined) return Promise.reject(new Error('invalid-upstream'))
  return chainedTunnel(target, upstream, timeoutMs)
}

function trackTunnel(tunnel: Tunnel, sockets: Set<Socket>): void {
  tunnel.socket.setTimeout(0)
  sockets.add(tunnel.socket)
  tunnel.socket.once('close', () => sockets.delete(tunnel.socket))
}

/** Start the listener; resolves only after `listen` succeeded. */
export async function startEgressServer(options: EgressServerOptions): Promise<EgressServer> {
  const host = options.host ?? '127.0.0.1'
  const modeOf = options.mode
  const record = options.record
  const sockets = new Set<Socket>()
  const connectTimeoutMs = options.connectTimeoutMs ?? CONNECT_TIMEOUT_MS
  const idleTimeoutMs = options.idleTimeoutMs ?? IDLE_TIMEOUT_MS

  const server = createHttpServer()
  let boundPort = options.port

  server.on('connection', (socket: Socket) => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
  })

  server.on('connect', (request: IncomingMessage, clientSocket: Socket, head: Buffer) => {
    const started = Date.now()
    const mode = modeOf()
    // The host hands the socket over raw; keep an error handler on it for every
    // branch, including the refusals before a tunnel exists.
    clientSocket.on('error', () => clientSocket.destroy())
    const target = parseEgressAuthority(request.url ?? '')

    if (target === undefined) {
      record({
        event: 'deny',
        decision: 'deny',
        enforced: mode === 'enforce',
        mode,
        reason: 'invalid-target',
        scheme: 'https',
      })
      writeTunnelDeny(clientSocket, 'invalid-target', undefined, '400 Bad Request')
      return
    }

    if (isSelfTarget(target, boundPort)) {
      record({
        event: 'deny',
        host: target.host,
        port: target.port,
        decision: 'deny',
        enforced: mode === 'enforce',
        mode,
        reason: 'invalid-target',
        scheme: 'https',
      })
      writeTunnelDeny(clientSocket, 'invalid-target', undefined, '400 Bad Request')
      return
    }

    const decision = options.policy.evaluate(target)
    const enforced = decision.action === 'deny' && mode === 'enforce'
    record({
      event: 'connect',
      host: target.host,
      port: target.port,
      decision: decision.action,
      enforced,
      mode,
      reason: decision.reason,
      scheme: 'https',
      ...(decision.rule === undefined ? {} : { rule: decision.rule }),
    })

    if (enforced) {
      writeTunnelDeny(clientSocket, decision.reason, decision.rule)
      return
    }

    let bytesIn = 0
    let bytesOut = 0
    let closed = false

    const finish = (outcome: 'ok' | 'error'): void => {
      if (closed) return
      closed = true
      record({
        event: 'close',
        host: target.host,
        port: target.port,
        decision: decision.action,
        enforced,
        mode,
        reason: decision.reason,
        scheme: 'https',
        bytesIn,
        bytesOut,
        durationMs: Date.now() - started,
        outcome,
      })
    }

    openTunnel(target, options, connectTimeoutMs).then(
      (tunnel: Tunnel) => {
        if (clientSocket.destroyed) {
          tunnel.socket.destroy()
          return
        }
        trackTunnel(tunnel, sockets)
        const targetSocket = tunnel.socket

        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        if (head.length > 0) {
          targetSocket.write(head)
          bytesOut += head.length
        }
        if (tunnel.leftover !== undefined) {
          clientSocket.write(tunnel.leftover)
          bytesIn += tunnel.leftover.length
        }

        clientSocket.on('data', (chunk: Buffer) => {
          bytesOut += chunk.length
        })
        targetSocket.on('data', (chunk: Buffer) => {
          bytesIn += chunk.length
        })

        clientSocket.setTimeout(idleTimeoutMs, () => clientSocket.destroy())
        targetSocket.setTimeout(idleTimeoutMs, () => targetSocket.destroy())

        clientSocket.pipe(targetSocket)
        targetSocket.pipe(clientSocket)

        clientSocket.on('close', () => {
          targetSocket.destroy()
          finish('ok')
        })
        targetSocket.on('close', () => {
          clientSocket.destroy()
          finish('ok')
        })
        clientSocket.on('error', () => finish('error'))
        targetSocket.on('error', () => finish('error'))
      },
      () => {
        record({
          event: 'error',
          host: target.host,
          port: target.port,
          decision: decision.action,
          mode,
          reason: 'upstream-failure',
          scheme: 'https',
          outcome: 'error',
        })
        writeTunnelDeny(clientSocket, 'upstream-failure', undefined, '502 Bad Gateway')
      },
    )
  })

  server.on('request', (request: IncomingMessage, response: ServerResponse) => {
    const started = Date.now()
    const mode = modeOf()
    const parsed = parseHttpTarget(request)

    if (parsed === undefined) {
      record({
        event: 'deny',
        decision: 'deny',
        enforced: mode === 'enforce',
        mode,
        reason: 'invalid-target',
        scheme: 'http',
      })
      writeHttpDeny(response, 'invalid-target', undefined, 400)
      return
    }

    const { target, path } = parsed
    if (isSelfTarget(target, boundPort)) {
      record({
        event: 'deny',
        host: target.host,
        port: target.port,
        decision: 'deny',
        enforced: mode === 'enforce',
        mode,
        reason: 'invalid-target',
        scheme: 'http',
      })
      writeHttpDeny(response, 'invalid-target', undefined, 400)
      return
    }
    const decision = options.policy.evaluate(target)
    const enforced = decision.action === 'deny' && mode === 'enforce'
    record({
      event: 'connect',
      host: target.host,
      port: target.port,
      decision: decision.action,
      enforced,
      mode,
      reason: decision.reason,
      scheme: 'http',
      ...(decision.rule === undefined ? {} : { rule: decision.rule }),
    })

    if (enforced) {
      writeHttpDeny(response, decision.reason, decision.rule)
      return
    }

    let bytesIn = 0
    let bytesOut = 0
    let closed = false
    const finish = (outcome: 'ok' | 'error'): void => {
      if (closed) return
      closed = true
      record({
        event: 'close',
        host: target.host,
        port: target.port,
        decision: decision.action,
        enforced,
        mode,
        reason: decision.reason,
        scheme: 'http',
        bytesIn,
        bytesOut,
        durationMs: Date.now() - started,
        outcome,
      })
    }

    const proxyRequest = httpRequest({
      host: target.host,
      port: target.port,
      method: request.method ?? 'GET',
      path,
      headers: forwardRequestHeaders(request.headers),
    })

    proxyRequest.setTimeout(connectTimeoutMs, () => {
      proxyRequest.destroy(new Error('upstream-timeout'))
    })

    proxyRequest.on('error', () => {
      if (!response.headersSent) {
        record({
          event: 'error',
          host: target.host,
          port: target.port,
          decision: decision.action,
          mode,
          reason: 'upstream-failure',
          scheme: 'http',
          outcome: 'error',
        })
        writeHttpDeny(response, 'upstream-failure', undefined, 502)
      } else {
        response.destroy()
      }
      finish('error')
    })

    proxyRequest.on('response', (proxyResponse: IncomingMessage) => {
      // Header names stay constant, so no upstream name ever reaches the socket.
      response.statusCode = proxyResponse.statusCode ?? 502
      for (const name of FORWARDED_RESPONSE_HEADERS) {
        const value = proxyResponse.headers[name]
        if (value !== undefined) response.setHeader(name, value)
      }
      proxyResponse.on('data', (chunk: Buffer) => {
        bytesIn += chunk.length
      })
      proxyResponse.on('end', () => finish('ok'))
      proxyResponse.on('error', () => finish('error'))
      proxyResponse.pipe(response)
    })

    request.on('data', (chunk: Buffer) => {
      bytesOut += chunk.length
    })
    request.on('error', () => {
      proxyRequest.destroy()
      finish('error')
    })
    response.on('close', () => {
      proxyRequest.destroy()
      finish('ok')
    })
    request.pipe(proxyRequest)
  })

  server.on('upgrade', (_request: IncomingMessage, socket: Socket) => {
    // WebSocket and other upgrades are not proxied; refuse instead of hanging.
    record({ event: 'error', mode: modeOf(), reason: 'unsupported-upgrade', outcome: 'error' })
    writeTunnelDeny(socket, 'invalid-target', undefined, '501 Not Implemented')
  })

  server.on('clientError', (_error: Error, socket: Socket) => {
    if (!socket.writable) {
      socket.destroy()
      return
    }
    socket.end('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
  })

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off('listening', onListening)
      reject(error)
    }
    const onListening = (): void => {
      server.off('error', onError)
      resolve()
    }
    server.once('error', onError)
    server.once('listening', onListening)
    server.listen(options.port, host)
  }).catch((error: unknown) => {
    options.logger?.warn(
      'Sensitive Guard: egress listener could not bind ' +
        host +
        ':' +
        String(options.port) +
        ' (' +
        (error instanceof Error ? ((error as NodeJS.ErrnoException).code ?? error.name) : 'error') +
        ').',
    )
    throw error
  })

  // A one-shot headless run must still be able to exit: the listener serves
  // traffic while anything else keeps the process alive, but never holds it open
  // after the agent reaches quiescence.
  server.unref()

  const address = server.address()
  boundPort = address !== null && typeof address === 'object' ? address.port : options.port

  return {
    port: boundPort,
    close(): Promise<void> {
      for (const socket of sockets) socket.destroy()
      sockets.clear()
      return new Promise<void>((resolve) => {
        server.close(() => resolve())
      })
    },
  }
}
