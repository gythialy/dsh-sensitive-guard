/**
 * Public redaction API. `createRedactor` binds the vendored rule table to one
 * validated config; `createPseudonymizer` exposes the keyed PII pseudonymizer
 * used internally and by tests. Secrets are never reversible; PII pseudonyms
 * are stable for as long as the key file survives.
 * @module dsh-sensitive-guard/redact
 */
import os from 'node:os'
import path from 'node:path'
import type { GuardConfig } from '../config.js'
import type { Logger, Redactor } from '../contracts.js'
import { createPseudonymizer, type Pseudonymizer } from '../pseudonym/index.js'
import { safeLogger } from '../util/logger.js'
import { dshHome, expandHome } from '../util/paths.js'
import { createEngine } from './engine.js'
import { resetSecretPlaceholderState } from './placeholders.js'
import { SECRET_RULES } from './rules.js'

export { createPseudonymizer, resetSecretPlaceholderState, SECRET_RULES }
export type { Pseudonymizer } from '../pseudonym/index.js'
export type { PseudonymizerOptions } from '../pseudonym/index.js'
export type { CompiledSecretRule } from './rules.js'

export interface RedactorOptions {
  config: GuardConfig
  /** Explicit PII key file; wins over `config.pii.keyFile`. */
  keyPath?: string
  logger?: Logger
  /** Home directory used by `~` expansion and the default `$DSH_HOME`. */
  home?: string
  /** Environment used to resolve `$DSH_HOME`. */
  env?: NodeJS.ProcessEnv
}

/**
 * Resolve the PII key file: explicit `keyPath`, then `config.pii.keyFile`,
 * then `$DSH_HOME/sensitive-guard-pii.key` (`~/.dsh` when unset).
 */
export function resolvePiiKeyPath(options: RedactorOptions): string {
  const home = options.home ?? os.homedir()
  const explicit =
    options.keyPath !== undefined && options.keyPath.trim().length > 0
      ? options.keyPath
      : options.config.pii.keyFile.trim().length > 0
        ? options.config.pii.keyFile
        : ''
  if (explicit.length > 0) return path.resolve(expandHome(explicit, home))
  return path.join(dshHome(options.env, options.home), 'sensitive-guard-pii.key')
}

/** Create the text/value/content redactor for one guard config. */
export function createRedactor(options: RedactorOptions): Redactor {
  const logger = safeLogger(options.logger)
  const keyPath = resolvePiiKeyPath(options)
  let pseudonymizer: Pseudonymizer | undefined

  const getPseudonymizer = (): Pseudonymizer => {
    if (pseudonymizer !== undefined) return pseudonymizer
    pseudonymizer = createPseudonymizer({ keyPath, logger })
    return pseudonymizer
  }

  return createEngine({
    maxScanBytes: options.config.limits.maxScanBytes,
    piiEnabled: options.config.pii.enabled,
    getPseudonymizer,
  })
}
