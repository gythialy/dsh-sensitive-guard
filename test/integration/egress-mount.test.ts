import { mkdtemp, readFile, rm } from 'node:fs/promises'
import {
  connect as netConnect,
  createServer as createNetServer,
  type Server as NetServer,
  type Socket,
} from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { resolveConfig } from '../../src/config.js'
import { apply } from '../../src/index.js'
import { createFakeContext, type FakeContext } from '../helpers/fake-ctx.js'

let dir: string
let auditPath: string

beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'sg-egress-'))
  auditPath = path.join(dir, 'audit.jsonl')
})

afterEach(async () => {
  vi.unstubAllEnvs()
  await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 20 })
})

function listen(server: NetServer): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (address === null || typeof address === 'string') {
        reject(new Error('no address'))
        return
      }
      resolve(address.port)
    })
  })
}

function closeServer(server: NetServer): Promise<void> {
  return new Promise<void>((resolve) => {
    server.close(() => resolve())
  })
}

async function freePort(): Promise<number> {
  const server = createNetServer()
  const port = await listen(server)
  await closeServer(server)
  return port
}

function tunnel(port: number, authority: string): Promise<{ status: number; socket: Socket }> {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host: '127.0.0.1', port })
    let buffer = ''
    const onData = (chunk: Buffer): void => {
      buffer += chunk.toString('latin1')
      const end = buffer.indexOf('\r\n\r\n')
      if (end < 0) return
      socket.off('data', onData)
      resolve({ status: Number.parseInt(buffer.slice(0, end).split(' ')[1] ?? '', 10), socket })
    }
    socket.on('data', onData)
    socket.once('connect', () =>
      socket.write('CONNECT ' + authority + ' HTTP/1.1\r\nHost: x\r\n\r\n'),
    )
    socket.once('error', reject)
  })
}

async function waitForAudit(check: (text: string) => boolean, timeoutMs = 4000): Promise<string> {
  const started = Date.now()
  let text = ''
  while (Date.now() - started < timeoutMs) {
    text = await readFile(auditPath, 'utf8').catch(() => '')
    if (check(text)) return text
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
  return text
}

describe('egress guard mount through apply()', () => {
  it('binds, audits, answers the command, and closes on dispose', async () => {
    const echoSockets = new Set<Socket>()
    const echo = createNetServer((socket: Socket) => {
      echoSockets.add(socket)
      socket.on('close', () => echoSockets.delete(socket))
      socket.on('data', (chunk: Buffer) => socket.write(chunk))
      socket.on('error', () => socket.destroy())
    })
    const echoPort = await listen(echo)
    const port = await freePort()
    vi.stubEnv('https_proxy', 'http://127.0.0.1:' + String(port))
    vi.stubEnv('HTTPS_PROXY', 'http://127.0.0.1:' + String(port))

    const fake: FakeContext = createFakeContext()
    const config = resolveConfig({
      mode: 'monitor',
      pii: { enabled: false },
      audit: { enabled: true, path: auditPath },
      egress: { enabled: true, port, canary: true, unknown: 'allow' },
    })

    const pending = apply(fake.ctx, config)
    expect(pending).toBeDefined()
    const dispose = await pending

    // The canary opens its own tunnel, so its record trails the mount record.
    const audit = await waitForAudit((text) => text.includes('"event":"canary"'))
    expect(audit).toContain('"event":"mount"')
    expect(audit).toContain('"reason":"env-ok"')
    expect(audit).toContain('"event":"canary"')

    const reply = await tunnel(port, '127.0.0.1:' + String(echoPort))
    expect(reply.status).toBe(200)
    reply.socket.destroy()

    const guardCommand = fake.commands.find((command) => command.name === 'guard')
    expect(guardCommand).toBeDefined()
    const result = (await guardCommand?.handler({ rawInput: 'egress status' })) as {
      kind: string
      text?: string
    }
    expect(result.kind).toBe('success')
    expect(result.text ?? '').toContain('listener: 127.0.0.1:' + String(port))
    expect(result.text ?? '').toContain('https_proxy points at this listener')

    await dispose?.()
    await expect(
      new Promise<void>((resolve, reject) => {
        const socket = netConnect({ host: '127.0.0.1', port })
        socket.once('connect', () => {
          socket.destroy()
          reject(new Error('listener still bound'))
        })
        socket.once('error', () => resolve())
      }),
    ).resolves.toBeUndefined()

    for (const socket of echoSockets) socket.destroy()
    await closeServer(echo)
  })

  it('warns and stays without coverage when the environment is not wired', async () => {
    const port = await freePort()
    vi.stubEnv('https_proxy', '')
    vi.stubEnv('HTTPS_PROXY', '')

    const fake = createFakeContext()
    const config = resolveConfig({
      mode: 'monitor',
      pii: { enabled: false },
      audit: { enabled: true, path: auditPath },
      egress: { enabled: true, port, canary: true },
    })

    const dispose = await apply(fake.ctx, config)
    const audit = await waitForAudit((text) => text.includes('"reason":"env-missing"'))
    expect(audit).toContain('"event":"mount"')
    expect(fake.warnings.join('\n')).toContain('https_proxy does not point at it')
    await dispose?.()
  })

  it('fails the plugin when the port is taken and fail-closed is on', async () => {
    const blocker = createNetServer()
    const port = await listen(blocker)
    vi.stubEnv('https_proxy', 'http://127.0.0.1:' + String(port))

    const fake = createFakeContext()
    const config = resolveConfig({
      mode: 'enforce',
      pii: { enabled: false },
      audit: { enabled: false },
      egress: { enabled: true, port, canary: false },
    })

    await expect(Promise.resolve(apply(fake.ctx, config))).rejects.toThrow(/could not bind/)
    await closeServer(blocker)
  })
})
