import { createHash } from 'node:crypto'
import type { JsonValue } from '../contracts.js'

/** Stable JSON serialization with sorted object keys. */
export function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']'
  const keys = Object.keys(value).sort()
  return (
    '{' + keys.map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key]!)).join(',') + '}'
  )
}

/** SHA-256 hex digest. */
export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex')
}

/** Path/argument digest used by the audit log: first 16 hex characters. */
export function shortHash(input: string): string {
  return sha256Hex(input).slice(0, 16)
}

/** Hash an arbitrary JSON value canonically. */
export function hashJson(value: JsonValue): string {
  return shortHash(canonicalJson(value))
}

/** Hash a filesystem path, normalizing separators and trailing slashes. */
export function hashPath(input: string): string {
  const normalized = input.replaceAll('\\', '/').replace(/\/+$/, '')
  return shortHash(normalized)
}
