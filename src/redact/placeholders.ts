/**
 * In-memory secret placeholder ids. A four-character base32 id is minted for
 * each unique original value and reused for the lifetime of the process; the
 * plaintext-to-id map is never persisted and secrets are never recoverable.
 * @module dsh-sensitive-guard/redact/placeholders
 */
import { randomBytes } from 'node:crypto'

/** Crockford-ish base32 alphabet required by the placeholder contract. */
const SECRET_ID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/** Original value -> minted id. The key is the only in-memory plaintext copy. */
const SECRET_IDS = new Map<string, string>()

/** Every id handed out, to keep distinct original values on distinct ids. */
const USED_IDS = new Set<string>()

/** Total possible ids; guards against exhausting the id space in a loop. */
const ID_SPACE = SECRET_ID_ALPHABET.length ** 4

/** Mint (or reuse) the id for one unique original value (exported for the engine). */
export function secretPlaceholderId(value: string): string {
  const existing = SECRET_IDS.get(value)
  if (existing !== undefined) return existing
  if (USED_IDS.size >= ID_SPACE) {
    // 1,048,576 distinct secrets in one process is not a supported workload;
    // failing loudly beats silently reusing an id for a different value.
    throw new Error('sensitive-guard: secret placeholder id space exhausted')
  }
  for (;;) {
    const bytes = randomBytes(4)
    let id = ''
    for (const byte of bytes) id += SECRET_ID_ALPHABET.charAt(byte & 31)
    if (USED_IDS.has(id)) continue
    USED_IDS.add(id)
    SECRET_IDS.set(value, id)
    return id
  }
}

/** Format the non-reversible placeholder for one secret match. */
export function secretPlaceholder(category: string, value: string): string {
  return `[SECRET:${category}:${secretPlaceholderId(value)}]`
}

/**
 * Test/DI helper: forget every minted secret id and its mapping. Afterwards a
 * previously redacted value receives a fresh random id.
 */
export function resetSecretPlaceholderState(): void {
  SECRET_IDS.clear()
  USED_IDS.clear()
}
