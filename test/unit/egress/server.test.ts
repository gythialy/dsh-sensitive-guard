import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import {
  createServer as createNetServer,
  connect as netConnect,
  type Server as NetServer,
  type Socket,
} from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import type { EgressRecord } from '../../../src/audit.js'
import { createEgressPolicy } from '../../../src/egress/policy.js'
import { startEgressServer, type EgressServer } from '../../../src/egress/server.js'

const cleanups: Array<() => Promise<void>> = []

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).toReversed()) await cleanup()
})

function listen(server: NetServer | HttpServer, port = 0): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const onError = (error: Error): void => reject(error)
    server.once('error', onError)
    server.listen(port, '127.0.0.1', () => {
      server.off('error', onError)
      const address = server.address()
      if (address === null || typeof address === 'string') {
        reject(new Error('no address'))
        return
      }
      resolve(address.port)
    })
  })
}

function closeServer(server: NetServer | HttpServer): Promise<void> {
  return new Promise<void>((resolve) => {
    server.close(() => resolve())
  })
}

interface Echo {
  port: number
  connections: number
  server: NetServer
}

async function startEcho(): Promise<Echo> {
  const state = { connections: 0 }
  const server = createNetServer((socket: Socket) => {
    state.connections += 1
    socket.on('data', (chunk: Buffer) => socket.write(chunk))
    socket.on('error', () => socket.destroy())
  })
  const port = await listen(server)
  cleanups.push(() => closeServer(server))
  return {
    port,
    server,
    get connections(): number {
      return state.connections
    },
  }
}

interface HttpOrigin {
  port: number
  requests: string[]
  /** Request headers as the origin saw them, for forwarding assertions. */
  headers: Array<Record<string, string | string[] | undefined>>
}

async function startHttpOrigin(): Promise<HttpOrigin> {
  const requests: string[] = []
  const headers: Array<Record<string, string | string[] | undefined>> = []
  const body = 'origin-ok'
  const server = createHttpServer((request, response) => {
    requests.push((request.method ?? 'GET') + ' ' + (request.url ?? ''))
    headers.push({ ...request.headers })
    response.writeHead(200, {
      'content-type': 'text/plain',
      'content-length': String(body.length),
      // Mirrored: standard header the proxy forwards.
      'cache-control': 'no-store',
      // Dropped: the response header set is constant, never upstream-named.
      'x-upstream-only': 'dropped',
    })
    response.end(body)
  })
  const port = await listen(server)
  cleanups.push(() => closeServer(server))
  return { port, requests, headers }
}

interface Guard {
  server: EgressServer
  records: EgressRecord[]
  port: number
}

async function startGuard(
  options: {
    allow?: string[]
    deny?: string[]
    unknown?: 'allow' | 'deny'
    mode?: () => 'monitor' | 'enforce'
    port?: number
    upstream?: string
  } = {},
): Promise<Guard> {
  const records: EgressRecord[] = []
  const server = await startEgressServer({
    port: options.port ?? 0,
    policy: createEgressPolicy({
      allow: options.allow ?? [],
      deny: options.deny ?? [],
      unknown: options.unknown ?? 'allow',
    }),
    mode: options.mode ?? (() => 'enforce'),
    record: (record) => records.push(record),
    ...(options.upstream === undefined ? {} : { upstream: options.upstream }),
  })
  cleanups.push(() => server.close())
  return { server, records, port: server.port }
}

interface ConnectReply {
  socket: Socket
  status: number
  headers: string
}

function connectTunnel(proxyPort: number, authority: string): Promise<ConnectReply> {
  return new Promise<ConnectReply>((resolve, reject) => {
    const socket = netConnect({ host: '127.0.0.1', port: proxyPort })
    let buffer = ''
    const onData = (chunk: Buffer): void => {
      buffer += chunk.toString('latin1')
      const end = buffer.indexOf('\r\n\r\n')
      if (end < 0) return
      socket.off('data', onData)
      const head = buffer.slice(0, end)
      const status = Number.parseInt(head.split(' ')[1] ?? '', 10)
      resolve({ socket, status, headers: head })
    }
    socket.on('data', onData)
    socket.once('connect', () => {
      socket.write('CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n\r\n')
    })
    socket.once('error', reject)
  })
}

function roundTrip(socket: Socket, payload: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    let data = ''
    const onData = (chunk: Buffer): void => {
      data += chunk.toString('latin1')
      if (data.length >= payload.length) {
        socket.off('data', onData)
        resolve(data)
      }
    }
    socket.on('data', onData)
    socket.once('error', reject)
    socket.write(payload)
  })
}

interface RawReply {
  status: number
  headers: string
  body: string
}

/** One absolute-form proxy request, parsed by Content-Length or socket end. */
function httpThroughProxy(proxyPort: number, url: string, extraHeaders = ''): Promise<RawReply> {
  return new Promise<RawReply>((resolve, reject) => {
    const socket = netConnect({ host: '127.0.0.1', port: proxyPort })
    let buffer = ''
    let settled = false

    const finish = (): void => {
      if (settled) return
      settled = true
      socket.destroy()
      const end = buffer.indexOf('\r\n\r\n')
      if (end < 0) {
        reject(new Error('no response headers'))
        return
      }
      const head = buffer.slice(0, end)
      const status = Number.parseInt(head.split(' ')[1] ?? '', 10)
      const body = buffer.slice(end + 4)
      const lengthMatch = /\r\ncontent-length:\s*(\d+)/i.exec(head)
      const expected = lengthMatch === null ? 0 : Number(lengthMatch[1])
      if (/\r\ntransfer-encoding:\s*chunked/i.test(head)) {
        if (!body.includes('0\r\n\r\n')) return
      } else if (body.length < expected) {
        return
      }
      resolve({ status, headers: head, body })
    }

    socket.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('latin1')
      finish()
    })
    socket.once('end', finish)
    socket.once('error', reject)
    socket.once('connect', () => {
      const host = new URL(url).host
      socket.write(
        'GET ' +
          url +
          ' HTTP/1.1\r\nHost: ' +
          host +
          '\r\nConnection: close\r\n' +
          extraHeaders +
          '\r\n',
      )
    })
  })
}

async function waitFor(check: () => boolean, timeoutMs = 3000): Promise<void> {
  const started = Date.now()
  while (!check()) {
    if (Date.now() - started > timeoutMs) throw new Error('timed out waiting for a record')
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
}

describe('egress CONNECT tunnel', () => {
  it('tunnels an allowed destination and records byte counts', async () => {
    const echo = await startEcho()
    const guard = await startGuard({ allow: ['127.0.0.1'] })

    const reply = await connectTunnel(guard.port, '127.0.0.1:' + String(echo.port))
    expect(reply.status).toBe(200)
    await expect(roundTrip(reply.socket, 'hello-guard')).resolves.toBe('hello-guard')
    reply.socket.destroy()

    await waitFor(() => guard.records.some((record) => record.event === 'close'))
    const connectRecord = guard.records.find((record) => record.event === 'connect')
    expect(connectRecord).toMatchObject({
      event: 'connect',
      host: '127.0.0.1',
      port: echo.port,
      decision: 'allow',
      enforced: false,
      scheme: 'https',
      reason: 'allow-list',
    })
    const closeRecord = guard.records.find((record) => record.event === 'close')
    expect(closeRecord).toMatchObject({ event: 'close', outcome: 'ok' })
    expect(closeRecord?.bytesOut ?? 0).toBeGreaterThan(0)
    expect(closeRecord?.bytesIn ?? 0).toBeGreaterThan(0)
    expect(echo.connections).toBe(1)
  })

  it('refuses a denied destination in enforce without dialling it', async () => {
    const echo = await startEcho()
    const guard = await startGuard({ deny: ['127.0.0.1'] })

    const reply = await connectTunnel(guard.port, '127.0.0.1:' + String(echo.port))
    expect(reply.status).toBe(403)
    expect(reply.headers.toLowerCase()).toContain('x-guard-reason: denied-by-rule')
    reply.socket.destroy()

    expect(echo.connections).toBe(0)
    await waitFor(() => guard.records.some((record) => record.event === 'connect'))
    expect(guard.records.find((record) => record.event === 'connect')).toMatchObject({
      decision: 'deny',
      enforced: true,
      reason: 'deny-list',
      rule: 'egress-deny[0]',
    })
  })

  it('passes a denied destination through in monitor mode and records it', async () => {
    const echo = await startEcho()
    const guard = await startGuard({ deny: ['127.0.0.1'], mode: () => 'monitor' })

    const reply = await connectTunnel(guard.port, '127.0.0.1:' + String(echo.port))
    expect(reply.status).toBe(200)
    await expect(roundTrip(reply.socket, 'abc')).resolves.toBe('abc')
    reply.socket.destroy()

    expect(guard.records.find((record) => record.event === 'connect')).toMatchObject({
      decision: 'deny',
      enforced: false,
      mode: 'monitor',
    })
  })

  it('refuses unknown destinations when the default is deny', async () => {
    const echo = await startEcho()
    const guard = await startGuard({ unknown: 'deny' })

    const reply = await connectTunnel(guard.port, '127.0.0.1:' + String(echo.port))
    expect(reply.status).toBe(403)
    expect(reply.headers.toLowerCase()).toContain('x-guard-reason: unknown-destination-blocked')
    reply.socket.destroy()
  })

  it('rejects a CONNECT authority without a port', async () => {
    const guard = await startGuard({})
    const reply = await connectTunnel(guard.port, 'example.com')
    expect(reply.status).toBe(400)
    expect(reply.headers.toLowerCase()).toContain('x-guard-reason: invalid-target')
    reply.socket.destroy()
  })
})

describe('egress plain-HTTP forward', () => {
  it('forwards an allowed absolute-form request and records it', async () => {
    const origin = await startHttpOrigin()
    const guard = await startGuard({ allow: ['127.0.0.1'] })

    const reply = await httpThroughProxy(
      guard.port,
      'http://127.0.0.1:' + String(origin.port) + '/a?b=1',
      'X-Api-Key: keep-me\r\n',
    )
    expect(reply.status).toBe(200)
    expect(reply.body).toBe('origin-ok')
    expect(origin.requests).toEqual(['GET /a?b=1'])
    // Tool auth lives in custom request headers, so those are forwarded.
    expect(origin.headers[0]?.['x-api-key']).toBe('keep-me')
    // Response headers are mirrored from a constant set; upstream-only names are not.
    expect(reply.headers.toLowerCase()).toContain('cache-control: no-store')
    expect(reply.headers.toLowerCase()).not.toContain('x-upstream-only')

    await waitFor(() => guard.records.some((record) => record.event === 'close'))
    expect(guard.records.find((record) => record.event === 'connect')).toMatchObject({
      scheme: 'http',
      decision: 'allow',
    })
    expect(guard.records.find((record) => record.event === 'close')?.bytesIn ?? 0).toBeGreaterThan(
      0,
    )
  })

  it('refuses a denied absolute-form request in enforce', async () => {
    const guard = await startGuard({ deny: ['127.0.0.1'] })

    const reply = await httpThroughProxy(guard.port, 'http://127.0.0.1:1/secret')
    expect(reply.status).toBe(403)
    expect(reply.headers.toLowerCase()).toContain('x-guard-reason: denied-by-rule')
  })
})

describe('egress upstream chaining', () => {
  it('chains a tunnel through an upstream proxy and preserves bytes', async () => {
    const echo = await startEcho()
    const upstream = await startGuard({})
    const guard = await startGuard({ upstream: 'http://127.0.0.1:' + String(upstream.port) })

    const reply = await connectTunnel(guard.port, '127.0.0.1:' + String(echo.port))
    expect(reply.status).toBe(200)
    await expect(roundTrip(reply.socket, 'chained')).resolves.toBe('chained')
    reply.socket.destroy()

    expect(upstream.records.find((record) => record.event === 'connect')).toMatchObject({
      host: '127.0.0.1',
      decision: 'allow',
    })
    expect(echo.connections).toBe(1)
  })

  it('surfaces an upstream refusal as a 502', async () => {
    const upstream = await startGuard({ deny: ['127.0.0.1'] })
    const guard = await startGuard({ upstream: 'http://127.0.0.1:' + String(upstream.port) })
    const echo = await startEcho()

    const reply = await connectTunnel(guard.port, '127.0.0.1:' + String(echo.port))
    expect(reply.status).toBe(502)
    expect(reply.headers.toLowerCase()).toContain('x-guard-reason: upstream-failure')
    reply.socket.destroy()
    expect(echo.connections).toBe(0)
  })
})

describe('egress self-target refusal', () => {
  it('refuses a CONNECT aimed at the listener itself', async () => {
    const guard = await startGuard({})
    const reply = await connectTunnel(guard.port, '127.0.0.1:' + String(guard.port))
    expect(reply.status).toBe(400)
    expect(reply.headers.toLowerCase()).toContain('x-guard-reason: invalid-target')
    reply.socket.destroy()
    expect(guard.records.find((record) => record.event === 'deny')).toMatchObject({
      reason: 'invalid-target',
    })
  })

  it('refuses an origin-form request aimed at the listener itself', async () => {
    const guard = await startGuard({})
    const reply = await httpThroughProxy(guard.port, 'http://127.0.0.1:' + String(guard.port) + '/')
    expect(reply.status).toBe(400)
    expect(reply.headers.toLowerCase()).toContain('x-guard-reason: invalid-target')
  })
})

describe('egress listener lifecycle', () => {
  it('rejects a second bind on a taken port', async () => {
    const guard = await startGuard({})
    await expect(
      startEgressServer({
        port: guard.port,
        policy: createEgressPolicy({ allow: [], deny: [], unknown: 'allow' }),
        mode: () => 'monitor',
        record: () => undefined,
      }),
    ).rejects.toThrow()
  })
})
