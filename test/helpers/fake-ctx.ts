import type { Context } from '@deepseek-ai/cordis'
import type { Logger } from '../../src/contracts.js'

export type Listener = (...args: unknown[]) => unknown

export interface FakeContext {
  ctx: Context
  listeners: Map<string, Listener[]>
  warnings: string[]
  /** First registered listener for an event (tests register one plugin). */
  listener(event: string): Listener
}

/** Minimal Cordis context: records event listeners with prepend semantics. */
export function createFakeContext(): FakeContext {
  const listeners = new Map<string, Listener[]>()
  const warnings: string[] = []
  const logger: Logger = {
    info() {},
    warn(message) {
      warnings.push(message)
    },
    debug() {},
  }

  const ctx = {
    logger,
    on(event: string, listener: Listener, options?: { prepend?: boolean }) {
      const list = listeners.get(event) ?? []
      if (options?.prepend === true) list.unshift(listener)
      else list.push(listener)
      listeners.set(event, list)
      return () => {
        const current = listeners.get(event) ?? []
        const index = current.indexOf(listener)
        if (index >= 0) current.splice(index, 1)
      }
    },
  }

  return {
    ctx: ctx as unknown as Context,
    listeners,
    warnings,
    listener(event) {
      const found = listeners.get(event)?.[0]
      if (!found) throw new Error('no listener registered for ' + event)
      return found
    },
  }
}
