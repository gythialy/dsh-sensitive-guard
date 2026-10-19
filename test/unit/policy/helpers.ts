import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { resolveConfig, type GuardConfig } from '../../../src/config.js'
import { clearPolicyCache } from '../../../src/policy/index.js'

/** Disposable project directory used as a session cwd. */
export class TempWorkspace {
  readonly dir: string

  constructor() {
    this.dir = mkdtempSync(path.join(os.tmpdir(), 'sg-policy-test-'))
  }

  resolve(...parts: string[]): string {
    return path.join(this.dir, ...parts)
  }

  write(relativePath: string, content: string): string {
    const file = this.resolve(relativePath)
    mkdirSync(path.dirname(file), { recursive: true })
    writeFileSync(file, content, 'utf8')
    return file
  }

  rules(yaml: string): string {
    return this.write('.dsh/rules.yaml', yaml)
  }

  cleanup(): void {
    clearPolicyCache()
    rmSync(this.dir, { recursive: true, force: true })
  }
}

export function configWith(overrides: Record<string, unknown> = {}): GuardConfig {
  return resolveConfig(overrides)
}

/** Isolated config: no vendored baseline and no generated path rules. */
export function bareConfig(extra: Record<string, unknown> = {}): GuardConfig {
  return configWith({
    policy: { builtin: false },
    paths: { allow: [], deny: [] },
    ...extra,
  })
}
