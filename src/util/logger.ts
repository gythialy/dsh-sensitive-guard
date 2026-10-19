import type { Logger } from '../contracts.js'

/** Logger that discards everything; useful in unit tests. */
export const noopLogger: Logger = {
  info() {},
  warn() {},
  debug() {},
}

/** Wrap an optional host logger so call sites never need optional chaining. */
export function safeLogger(logger?: Partial<Logger> | undefined): Logger {
  if (!logger) return noopLogger
  return {
    info: (message) => logger.info?.(message),
    warn: (message) => logger.warn?.(message),
    debug: (message) => logger.debug?.(message),
  }
}
