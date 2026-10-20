/**
 * Loopback canary probe for the egress guard. It proves the listener answers on
 * the port the launch environment names, instead of claiming coverage from
 * configuration alone (design D4b / §19.3).
 * @module dsh-sensitive-guard/egress/canary
 */
import {
  createServer as createNetServer,
  connect as netConnect,
  type AddressInfo,
  type Socket,
} from 'node:net'

/** Payload echoed through the tunnel; recognizable in a capture, never a secret. */
const CANARY_PAYLOAD = Buffer.from('sensitive-guard-canary')

/** Why a probe failed, when it did. */
export type CanaryCode = 'ok' | 'refused' | 'timeout' | 'denied' | 'protocol' | 'echo-mismatch'

export interface CanaryResult {
  ok: boolean
  code: CanaryCode
  latencyMs: number
  /** CONNECT reply status, when the listener answered. */
  status?: number
}

export interface CanaryOptions {
  host?: string
  timeoutMs?: number
}

function closeServer(server: ReturnType<typeof createNetServer>): Promise<void> {
  return new Promise<void>((resolve) => {
    server.close(() => resolve())
  })
}

/**
 * Open an echo server on an ephemeral loopback port, tunnel to it through the
 * guard, and verify the payload survives. The probe exercises the same
 * CONNECT path a client uses, so a bound-but-broken listener fails here.
 */
export async function runEgressCanary(
  port: number,
  options: CanaryOptions = {},
): Promise<CanaryResult> {
  const started = Date.now()
  const host = options.host ?? '127.0.0.1'
  const timeoutMs = options.timeoutMs ?? 3000

  const echo = createNetServer((socket: Socket) => {
    socket.on('data', (chunk: Buffer) => socket.write(chunk))
    socket.on('error', () => socket.destroy())
  })

  try {
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error): void => {
        echo.off('listening', onListening)
        reject(error)
      }
      const onListening = (): void => {
        echo.off('error', onError)
        resolve()
      }
      echo.once('error', onError)
      echo.once('listening', onListening)
      echo.listen(0, host)
    })
  } catch {
    return { ok: false, code: 'refused', latencyMs: Date.now() - started }
  }

  const address = echo.address() as AddressInfo | null
  const echoPort = address === null ? 0 : address.port

  try {
    return await new Promise<CanaryResult>((resolve) => {
      const socket = netConnect({ host, port })
      let settled = false
      let phase: 'headers' | 'echo' = 'headers'
      let buffer = Buffer.alloc(0)

      const finish = (result: Omit<CanaryResult, 'latencyMs'>): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        socket.destroy()
        resolve({ ...result, latencyMs: Date.now() - started })
      }

      const timer = setTimeout(() => finish({ ok: false, code: 'timeout' }), timeoutMs)

      socket.once('connect', () => {
        socket.write(
          'CONNECT ' +
            host +
            ':' +
            String(echoPort) +
            ' HTTP/1.1\r\nHost: ' +
            host +
            ':' +
            String(echoPort) +
            '\r\n\r\n',
        )
      })

      socket.on('data', (chunk: Buffer) => {
        buffer = Buffer.concat([buffer, chunk])
        if (phase === 'headers') {
          const end = buffer.indexOf('\r\n\r\n')
          if (end < 0) return
          const head = buffer.subarray(0, end).toString('latin1')
          buffer = buffer.subarray(end + 4)
          const status = Number.parseInt(head.split(' ')[1] ?? '', 10)
          if (Number.isNaN(status)) {
            finish({ ok: false, code: 'protocol' })
            return
          }
          if (status === 403 || status === 407) {
            finish({ ok: false, code: 'denied', status })
            return
          }
          if (status !== 200) {
            finish({ ok: false, code: 'protocol', status })
            return
          }
          phase = 'echo'
          socket.write(CANARY_PAYLOAD)
        }
        if (phase === 'echo' && buffer.length >= CANARY_PAYLOAD.length) {
          if (!buffer.subarray(0, CANARY_PAYLOAD.length).equals(CANARY_PAYLOAD)) {
            finish({ ok: false, code: 'echo-mismatch', status: 200 })
            return
          }
          finish({ ok: true, code: 'ok', status: 200 })
        }
      })

      socket.once('error', (error: Error) => {
        const code = (error as NodeJS.ErrnoException).code
        finish({ ok: false, code: code === 'ECONNREFUSED' ? 'refused' : 'protocol' })
      })
      socket.once('close', () => finish({ ok: false, code: 'refused' }))
    })
  } finally {
    await closeServer(echo)
  }
}
