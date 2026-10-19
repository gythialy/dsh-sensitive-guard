import { mkdtempSync, rmSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import type { Logger, Redactor } from '../../../src/contracts.js'
import type { Level } from '../../../src/contracts.js'
import { resolveConfig, type GuardConfig } from '../../../src/config.js'
import { createRedactor } from '../../../src/redact/index.js'

export interface ConfigOverrides {
  piiEnabled?: boolean
  maxScanBytes?: number
}

const tempDirs: string[] = []

/** Tracked temp directory; removed by {@link cleanupTempDirs}. */
export function tempDir(prefix = 'dsh-redact-'): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), prefix))
  tempDirs.push(dir)
  return dir
}

/** Remove every temp directory created through {@link tempDir}. */
export function cleanupTempDirs(): void {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
}

/** Fresh 32-byte key file path inside a new temp directory. */
export function keyPathInTempDir(): string {
  return path.join(tempDir(), 'sensitive-guard-pii.key')
}

/** Complete guard config with test-friendly defaults. */
export function configFor(level: Level, overrides: ConfigOverrides = {}): GuardConfig {
  return resolveConfig({
    levels: { input: level, output: level },
    pii: { enabled: overrides.piiEnabled ?? true },
    limits: { maxScanBytes: overrides.maxScanBytes ?? 4 * 1024 * 1024 },
  })
}

/** Redactor bound to a fresh temp PII key file. */
export function redactorFor(level: Level, overrides: ConfigOverrides = {}): Redactor {
  return createRedactor({ config: configFor(level, overrides), keyPath: keyPathInTempDir() })
}

/** Logger stub that records warnings without emitting anything. */
export function captureLogger(): { logger: Logger; warnings: string[] } {
  const warnings: string[] = []
  return {
    warnings,
    logger: {
      info() {},
      debug() {},
      warn(message: string) {
        warnings.push(message)
      },
    },
  }
}
