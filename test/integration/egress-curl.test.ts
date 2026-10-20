/**
 * Real-child coverage for the egress guard: a spawned `curl` with `-x` uses the
 * same CONNECT path a tool or MCP child uses, so an allow and a denial are
 * verified end to end instead of only through the in-process client.
 */
import { execFile } from 'node:child_process'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import type { Server as NetServer } from 'node:net'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'
import { createEgressPolicy } from '../../src/egress/policy.js'
import { startEgressServer, type EgressServer } from '../../src/egress/server.js'

const exec = promisify(execFile)
const cleanups: Array<() => Promise<void>> = []

const hasCurl = await exec('curl', ['--version'])
  .then(() => true)
  .catch(() => false)

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup()
})

function listen(server: NetServer | HttpServer): Promise<number> {
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

function closeServer(server: NetServer | HttpServer): Promise<void> {
  return new Promise<void>((resolve) => {
    server.close(() => resolve())
  })
}

describe.skipIf(!hasCurl)('egress guard with a real curl child', () => {
  it('forwards an allowed plain-HTTP request through the proxy', async () => {
    const origin = createHttpServer((request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain', 'content-length': '9' })
      response.end('origin-ok')
    })
    const originPort = await listen(origin)
    cleanups.push(() => closeServer(origin))

    const guard: EgressServer = await startEgressServer({
      port: 0,
      policy: createEgressPolicy({ allow: ['127.0.0.1'], deny: [], unknown: 'allow' }),
      mode: () => 'enforce',
      record: () => undefined,
    })
    cleanups.push(() => guard.close())

    const { stdout } = await exec('curl', [
      '-sS',
      '--noproxy',
      '',
      '-x',
      'http://127.0.0.1:' + String(guard.port),
      'http://127.0.0.1:' + String(originPort) + '/hello',
    ])
    expect(stdout).toBe('origin-ok')
  })

  it('refuses a denied CONNECT before any dial happens', async () => {
    const guard: EgressServer = await startEgressServer({
      port: 0,
      policy: createEgressPolicy({ allow: [], deny: ['blocked.example'], unknown: 'allow' }),
      mode: () => 'enforce',
      record: () => undefined,
    })
    cleanups.push(() => guard.close())

    const failure = await exec('curl', [
      '-sS',
      '--noproxy',
      '',
      '-x',
      'http://127.0.0.1:' + String(guard.port),
      'https://blocked.example/',
    ]).then(
      () => undefined,
      (error: { code?: number; stderr?: string }) => error,
    )
    expect(failure).toBeDefined()
    // curl reports a refused tunnel as code 7 with the guard's status code.
    expect(failure?.stderr ?? '').toContain('CONNECT tunnel failed, response 403')
  })
})
