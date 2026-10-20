import {
  createServer as createNetServer,
  connect as netConnect,
  type Server as NetServer,
  type Socket,
} from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import type { AuditLog, EgressRecord } from '../../../src/audit.js'
import {
  mountEgress,
  proxyEnvMatches,
  resolveProxyEnv,
  sanitizeProxyValue,
  type EgressController,
} from '../../../src/egress/index.js'
import { resolveConfig } from '../../../src/config.js'
import { noopLogger } from '../../../src/util/logger.js'

const cleanups: Array<() => Promise<void>> = []

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).toReversed()) await cleanup()
})

function closeServer(server: NetServer): Promise<void> {
  return new Promise<void>((resolve) => {
    server.close(() => resolve())
  })
}

async function listen(server: NetServer, port = 0): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', () => {
      const address = server.address()
      if (address === null || typeof address === 'string') {
        reject(new Error('no address'))
        return
      }
      resolve(address.port)
    })
  })
}

async function freePort(): Promise<number> {
  const server = createNetServer()
  const port = await listen(server)
  await closeServer(server)
  return port
}

interface AuditSpy {
  audit: AuditLog
  records: EgressRecord[]
}

function auditSpy(): AuditSpy {
  const records: EgressRecord[] = []
  const audit = {
    egress: (record: EgressRecord) => records.push(record),
    decision: () => undefined,
    redact: () => undefined,
    error: () => undefined,
    flush: async () => undefined,
    path: '',
  } as unknown as AuditLog
  return { audit, records }
}

async function mount(
  overrides: Record<string, unknown> = {},
  env: NodeJS.ProcessEnv = {},
): Promise<{ controller: EgressController; records: EgressRecord[] }> {
  const spy = auditSpy()
  const config = resolveConfig({ egress: overrides })
  const controller = await mountEgress({
    config: config.egress,
    modeOf: () => config.mode,
    audit: spy.audit,
    logger: noopLogger,
    env,
  })
  cleanups.push(() => controller.close())
  return { controller, records: spy.records }
}

describe('egress proxy environment', () => {
  it('prefers the lowercase variable and treats a blank value as unset', () => {
    expect(
      resolveProxyEnv({ https_proxy: 'http://127.0.0.1:41999', HTTPS_PROXY: 'http://other:1' }),
    ).toBe('http://127.0.0.1:41999')
    expect(resolveProxyEnv({ HTTPS_PROXY: 'http://127.0.0.1:1' })).toBe('http://127.0.0.1:1')
    expect(resolveProxyEnv({ https_proxy: '   ' })).toBeUndefined()
    expect(resolveProxyEnv({})).toBeUndefined()
  })

  it('matches only a plain-http loopback value on the configured port', () => {
    expect(proxyEnvMatches('http://127.0.0.1:41999', 41_999)).toBe(true)
    expect(proxyEnvMatches('http://localhost:41999', 41_999)).toBe(true)
    expect(proxyEnvMatches('http://[::1]:41999/', 41_999)).toBe(true)
    expect(proxyEnvMatches('http://127.0.0.1:41999', 41_998)).toBe(false)
    expect(proxyEnvMatches('https://127.0.0.1:41999', 41_999)).toBe(false)
    expect(proxyEnvMatches('http://user:pass@127.0.0.1:41999', 41_999)).toBe(false)
    expect(proxyEnvMatches('socks5://127.0.0.1:41999', 41_999)).toBe(false)
    expect(proxyEnvMatches('not a url', 41_999)).toBe(false)
    expect(proxyEnvMatches(undefined, 41_999)).toBe(false)
  })

  it('strips credentials before a proxy value is displayed', () => {
    expect(sanitizeProxyValue('http://user:secret@127.0.0.1:41999')).toBe('http://127.0.0.1:41999')
    expect(sanitizeProxyValue('nonsense')).toBe('(invalid proxy value)')
  })
})

describe('egress mount', () => {
  it('binds, records the mount, and reports env wiring', async () => {
    const port = await freePort()
    const { controller, records } = await mount(
      { enabled: true, port, canary: true },
      { https_proxy: 'http://127.0.0.1:' + String(port) },
    )

    expect(controller.bound).toBe(true)
    expect(controller.port).toBe(port)
    const snapshot = controller.snapshot()
    expect(snapshot).toMatchObject({
      enabled: true,
      bound: true,
      host: '127.0.0.1',
      port,
      mode: 'monitor',
      unknown: 'allow',
      envMatches: true,
      proxyEnv: 'http://127.0.0.1:' + String(port),
    })
    expect(records.find((record) => record.event === 'mount')?.reason).toBe('env-ok')
    expect(records.find((record) => record.event === 'canary')?.outcome).toBe('ok')
  })

  it('warns and reports a mismatch when the environment does not name it', async () => {
    const port = await freePort()
    const { controller, records } = await mount({ enabled: true, port, canary: false }, {})
    const snapshot = controller.snapshot()
    expect(snapshot.bound).toBe(true)
    expect(snapshot.envMatches).toBe(false)
    expect(snapshot.proxyEnv).toBeUndefined()
    expect(records.find((record) => record.event === 'mount')?.reason).toBe('env-missing')
  })

  it('counts tunnels and keeps recent destinations', async () => {
    const echo = createNetServer((socket: Socket) => {
      socket.on('data', (chunk: Buffer) => socket.write(chunk))
      socket.on('error', () => socket.destroy())
    })
    const echoPort = await listen(echo)
    cleanups.push(() => closeServer(echo))

    const port = await freePort()
    const { controller } = await mount({ enabled: true, port, canary: false }, {})

    const socket = netConnect({ host: '127.0.0.1', port })
    await new Promise<void>((resolve, reject) => {
      socket.once('error', reject)
      socket.once('connect', () => {
        socket.write('CONNECT 127.0.0.1:' + String(echoPort) + ' HTTP/1.1\r\nHost: x\r\n\r\n')
      })
      socket.once('data', () => resolve())
    })
    socket.destroy()

    const deadline = Date.now() + 2000
    while (controller.snapshot().counts.tunnels === 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10))
    }
    const snapshot = controller.snapshot()
    expect(snapshot.counts.tunnels).toBe(1)
    expect(snapshot.counts.allowed).toBe(1)
    expect(snapshot.recent).toEqual([
      {
        host: '127.0.0.1',
        port: echoPort,
        decision: 'allow',
        enforced: false,
        reason: 'unknown-allow',
      },
    ])
  })

  it('refuses to mount in fail-closed mode when the port is taken', async () => {
    const blocker = createNetServer()
    const port = await listen(blocker)
    cleanups.push(() => closeServer(blocker))
    const spy = auditSpy()
    const config = resolveConfig({ egress: { enabled: true, port } })
    await expect(
      mountEgress({
        config: config.egress,
        modeOf: () => config.mode,
        audit: spy.audit,
        logger: noopLogger,
        env: {},
      }),
    ).rejects.toThrow(/could not bind/)
    expect(spy.records.find((record) => record.event === 'error')?.reason).toBe('bind-failed')
  })

  it('mounts unbound when failClosed is off and reports it', async () => {
    const blocker = createNetServer()
    const port = await listen(blocker)
    cleanups.push(() => closeServer(blocker))
    const { controller } = await mount(
      { enabled: true, port, canary: false, failClosed: false },
      {},
    )
    expect(controller.bound).toBe(false)
    expect(controller.snapshot().bound).toBe(false)
  })

  it('rejects a port outside the TCP range', async () => {
    await expect(mount({ enabled: true, port: 0 })).rejects.toThrow(/between 1 and 65535/)
    await expect(mount({ enabled: true, port: 70_000 })).rejects.toThrow(/between 1 and 65535/)
  })

  it('runs the canary on demand', async () => {
    const port = await freePort()
    const { controller, records } = await mount({ enabled: true, port, canary: false }, {})
    await expect(controller.canary()).resolves.toMatchObject({ ok: true })
    expect(records.filter((record) => record.event === 'canary')).toHaveLength(1)
  })
})
