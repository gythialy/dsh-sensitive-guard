/**
 * Keyed, stable PII pseudonyms. `[[PII_<TYPE>_<hash8>]]` carries the first
 * eight hex characters of HMAC-SHA256(key, '<TYPE>:' + normalized value), so
 * the same value maps to the same pseudonym across calls, sessions, and
 * restarts while the key file stays private (0600).
 *
 * The HMAC-keyed pseudonym technique follows dsh-pii-anonymizer 0.2.0 (MIT,
 * Copyright (c) 2026 JWE24-code) as a design reference; this implementation was
 * rewritten for dsh-sensitive-guard.
 * @module dsh-sensitive-guard/pseudonym
 */
import { createHmac, randomBytes } from 'node:crypto'
import { chmodSync, closeSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import type { Logger } from '../contracts.js'
import { expandHome } from '../util/paths.js'
import { safeLogger } from '../util/logger.js'

/** Keyed pseudonymizer used for PII categories. */
export interface Pseudonymizer {
  /** Return the stable `[[PII_<TYPE>_<hash8>]]` placeholder for one value. */
  id(type: string, value: string): string
  /**
   * Resolve a placeholder minted in this process. Only populated when
   * `record` is enabled (the `pii.restore` opt-in); the map is memory-only.
   */
  get(placeholder: string): string | undefined
}

export interface PseudonymizerOptions {
  /** Explicit 32-byte key; wins over `keyPath`. */
  key?: Buffer
  /** Key file path; missing files are created with mode 0600. */
  keyPath?: string
  logger?: Logger
  /** Keep a process-memory placeholder → original map for `/guard restore`. */
  record?: boolean
}

const KEY_BYTES = 32
const KEY_FILE_MODE = 0o600
const KEY_DIR_MODE = 0o700

/** Process-wide fallback so every redactor in this process agrees. */
let processFallbackKey: Buffer | undefined
let warnedFallback = false

/** Normalize a PII value before hashing; category-specific by design. */
export function normalizePiiValue(type: string, value: string): string {
  switch (type) {
    case 'email':
      return value.trim().toLowerCase()
    case 'phone-cn':
    case 'phone-intl':
    case 'credit-card':
    case 'ssn-us':
      return value.replace(/\D/g, '')
    case 'id-cn':
      return value.trim().toUpperCase()
    default:
      return value.trim()
  }
}

/** `phone-cn` -> `PHONE_CN`; non-alphanumerics become underscores. */
export function piiTypeLabel(type: string): string {
  return type.toUpperCase().replace(/[^A-Z0-9]+/g, '_')
}

/** Build the keyed placeholder from an already-resolved key. */
export function piiPlaceholder(type: string, value: string, key: Buffer): string {
  const label = piiTypeLabel(type)
  const digest = createHmac('sha256', key)
    .update(`${label}:${normalizePiiValue(type, value)}`, 'utf8')
    .digest('hex')
  return `[[PII_${label}_${digest.slice(0, 8)}]]`
}

function fallbackKey(logger: Logger, reason: string): Buffer {
  if (!warnedFallback) {
    warnedFallback = true
    logger.warn(`sensitive-guard: ${reason}; using an ephemeral process key`)
  }
  processFallbackKey ??= randomBytes(KEY_BYTES)
  return processFallbackKey
}

type ExistingKey =
  | { kind: 'ok'; key: Buffer }
  | { kind: 'missing' }
  | { kind: 'error'; reason: string }

function readExistingKey(keyPath: string): ExistingKey {
  let data: Buffer
  try {
    data = readFileSync(keyPath)
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return { kind: 'missing' }
    return { kind: 'error', reason: 'the PII key file is unreadable' }
  }
  if (data.length !== KEY_BYTES)
    return { kind: 'error', reason: 'the PII key file has an invalid length' }
  return { kind: 'ok', key: data }
}

/** Read or atomically create the key file, falling back to a process key. */
function loadKeyFile(keyPath: string, logger: Logger): Buffer {
  const existing = readExistingKey(keyPath)
  if (existing.kind === 'ok') return existing.key
  if (existing.kind === 'error') return fallbackKey(logger, existing.reason)

  try {
    mkdirSync(path.dirname(keyPath), { recursive: true, mode: KEY_DIR_MODE })
    const fresh = randomBytes(KEY_BYTES)
    try {
      const fd = openSync(keyPath, 'wx', KEY_FILE_MODE)
      try {
        writeSync(fd, fresh)
      } finally {
        closeSync(fd)
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      // Lost the create race: another process wrote the key first.
      const raced = readExistingKey(keyPath)
      if (raced.kind === 'ok') return raced.key
      return fallbackKey(
        logger,
        raced.kind === 'error' ? raced.reason : 'the PII key file is unavailable',
      )
    }
    try {
      chmodSync(keyPath, KEY_FILE_MODE)
    } catch {
      // Best effort: the create mode already requested 0600.
    }
    return fresh
  } catch {
    return fallbackKey(logger, 'the PII key file could not be created')
  }
}

/**
 * Resolve the HMAC key: explicit key, key file (read/create), or a shared
 * process-random key when neither is available.
 */
export function resolvePiiKey(options: PseudonymizerOptions = {}): Buffer {
  const logger = safeLogger(options.logger)
  if (options.key !== undefined && options.key.length > 0) return options.key
  const keyPath = options.keyPath?.trim()
  if (keyPath === undefined || keyPath.length === 0) {
    return fallbackKey(logger, 'no PII key file is configured')
  }
  return loadKeyFile(expandHome(keyPath, os.homedir()), logger)
}

/** Create a synchronous keyed pseudonymizer. */
export function createPseudonymizer(options: PseudonymizerOptions = {}): Pseudonymizer {
  const key = resolvePiiKey(options)
  const restoreTable = options.record === true ? new Map<string, string>() : undefined
  return {
    id(type: string, value: string): string {
      const placeholder = piiPlaceholder(type, value, key)
      restoreTable?.set(placeholder, value)
      return placeholder
    },
    get(placeholder: string): string | undefined {
      return restoreTable?.get(placeholder)
    },
  }
}
