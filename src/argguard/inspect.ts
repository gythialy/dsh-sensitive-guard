/**
 * Argument inspection for the interception layer: bound the amount of data the
 * guard walks and detect credentials that would otherwise leave the host as a
 * tool argument. Detection is delegated to the redaction rules.
 * @module dsh-sensitive-guard/argguard
 */
import type { Redactor } from '../contracts.js'
import { utf8ByteLength } from '../util/bytes.js'

export interface ArgumentInspection {
  /** Serialized arguments exceed `limits.maxArgsBytes`. */
  tooLarge: boolean
  /** A tier-0 secret rule matched somewhere in the arguments. */
  hasSecret: boolean
  bytes: number
}

/**
 * Walk a JSON-like argument tree, never logging values. Circular structures
 * are treated as too large/invalid rather than crashing the hook.
 */
export function inspectArguments(
  value: unknown,
  redactor: Redactor,
  maxArgsBytes: number,
): ArgumentInspection {
  let serialized: string
  try {
    serialized = JSON.stringify(value) ?? ''
  } catch {
    return { tooLarge: true, hasSecret: false, bytes: Number.POSITIVE_INFINITY }
  }
  const bytes = utf8ByteLength(serialized)
  if (bytes > maxArgsBytes) return { tooLarge: true, hasSecret: false, bytes }

  let hasSecret = false
  const visit = (node: unknown): void => {
    if (hasSecret) return
    if (typeof node === 'string') {
      if (redactor.scan(node, 'minimal')) hasSecret = true
      return
    }
    if (Array.isArray(node)) {
      for (const item of node) visit(item)
      return
    }
    if (node !== null && typeof node === 'object') {
      for (const item of Object.values(node as Record<string, unknown>)) visit(item)
    }
  }
  visit(value)
  return { tooLarge: false, hasSecret, bytes }
}
