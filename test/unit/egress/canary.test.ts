import { createServer as createNetServer, type Server as NetServer, type Socket } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import { runEgressCanary } from '../../../src/egress/canary.js'
import { createEgressPolicy } from '../../../src/egress/policy.js'
import { startEgressServer } from '../../../src/egress/server.js'

const cleanups: Array<() => Promise<void>> = []

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).toReversed()) await cleanup()
})

function closeServer(server: NetServer): Promise<void> {
  return new Promise<void>((resolve) => {
    server.close(() => resolve())
  })
}

async function listen(server: NetServer): Promise<number> {
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

async function guardWith(options: {
  deny?: string[]
  mode?: 'monitor' | 'enforce'
}): Promise<number> {
  const server = await startEgressServer({
    port: 0,
    policy: createEgressPolicy({
      allow: [],
      deny: options.deny ?? [],
      unknown: 'allow',
    }),
    mode: () => options.mode ?? 'enforce',
    record: () => undefined,
  })
  cleanups.push(() => server.close())
  return server.port
}

describe('egress canary', () => {
  it('proves an allowed loopback tunnel echoes the payload', async () => {
    const port = await guardWith({})
    const result = await runEgressCanary(port, { timeoutMs: 2000 })
    expect(result).toMatchObject({ ok: true, code: 'ok', status: 200 })
    expect(result.latencyMs).toBeGreaterThanOrEqual(0)
  })

  it('reports a policy denial distinctly from a dead listener', async () => {
    const port = await guardWith({ deny: ['127.0.0.1'] })
    await expect(runEgressCanary(port)).resolves.toMatchObject({
      ok: false,
      code: 'denied',
      status: 403,
    })
  })

  it('reports a refused connection when nothing listens', async () => {
    const server = createNetServer()
    const port = await listen(server)
    await closeServer(server)
    const result = await runEgressCanary(port, { timeoutMs: 500 })
    expect(result).toMatchObject({ ok: false, code: 'refused' })
  })

  it('times out on a listener that never answers', async () => {
    const silentSockets = new Set<Socket>()
    const silent = createNetServer((socket: Socket) => {
      silentSockets.add(socket)
      socket.on('close', () => silentSockets.delete(socket))
    })
    const port = await listen(silent)
    cleanups.push(() => {
      for (const socket of silentSockets) socket.destroy()
      return closeServer(silent)
    })
    const result = await runEgressCanary(port, { timeoutMs: 100 })
    expect(result).toMatchObject({ ok: false, code: 'timeout' })
  })
})
