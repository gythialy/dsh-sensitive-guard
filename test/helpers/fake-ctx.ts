import type { Context } from '@deepseek-ai/cordis'
import type { Logger } from '../../src/contracts.js'

export type Listener = (...args: unknown[]) => unknown

export interface RegisteredCommand {
  name: string
  description: string
  input?: { hint: string }
  handler: (invocation: { rawInput: string }) => unknown
}

export interface FakeContext {
  ctx: Context
  listeners: Map<string, Listener[]>
  warnings: string[]
  commands: RegisteredCommand[]
  /** First registered listener for an event (tests register one plugin). */
  listener(event: string): Listener
}

/** Minimal Cordis context: records listeners, commands, and prepend semantics. */
export function createFakeContext(services: Record<string, unknown> = {}): FakeContext {
  const listeners = new Map<string, Listener[]>()
  const warnings: string[] = []
  const commands: RegisteredCommand[] = []
  const logger: Logger = {
    info() {},
    warn(message) {
      warnings.push(message)
    },
    debug() {},
  }

  const commandCtx = {
    commands: {
      register(definition: RegisteredCommand) {
        commands.push(definition)
        return () => undefined
      },
    },
  }

  const ctx = {
    logger,
    get(name: string) {
      return services[name]
    },
    inject(_services: string[], callback: (scope: unknown) => void) {
      callback(commandCtx)
      return () => undefined
    },
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
    commands,
    listener(event) {
      const found = listeners.get(event)?.[0]
      if (!found) throw new Error('no listener registered for ' + event)
      return found
    },
  }
}
