import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import { clearPolicyCache, loadRuleSet } from '../../../src/policy/index.js'
import { configWith, TempWorkspace } from './helpers.js'

const fixtureDir = fileURLToPath(new URL('../../fixtures/policy/', import.meta.url))

let workspace: TempWorkspace | undefined

afterEach(() => {
  workspace?.cleanup()
  workspace = undefined
})

function newWorkspace(): TempWorkspace {
  workspace = new TempWorkspace()
  return workspace
}

function isolatedConfig(rulesFile?: string, maxRules = 256) {
  return configWith({
    policy: {
      ...(rulesFile === undefined ? {} : { rulesFile }),
      builtin: false,
      maxRules,
    },
    paths: { allow: [], deny: [] },
  })
}

describe('rule loading', () => {
  it('loads and validates a project rule file', () => {
    const config = isolatedConfig('rules-valid.yaml')
    const loaded = loadRuleSet({ config, cwd: fixtureDir, platform: 'darwin' })

    expect(loaded.userCount).toBe(2)
    expect(loaded.builtinCount).toBe(0)
    expect(loaded.pathRuleCount).toBe(0)
    expect(loaded.rules.map((rule) => rule.id)).toEqual([
      'inspect-fixture-allow',
      'inspect-fixture-deny',
    ])
    expect(loaded.rules[0]!.priority).toBe(5)
    expect(loaded.rules[1]!.priority).toBe(1)
  })

  it('appends generated path rules and the builtin baseline in priority order', () => {
    const ws = newWorkspace()
    const config = configWith({
      policy: { builtin: true },
      paths: { allow: ['**/.env.example'], deny: ['**/.env'] },
    })
    const loaded = loadRuleSet({ config, cwd: ws.dir, platform: 'darwin' })

    expect(loaded.userCount).toBe(0)
    expect(loaded.pathRuleCount).toBe(2)
    expect(loaded.builtinCount).toBeGreaterThan(10)
    const ids = loaded.rules.map((rule) => rule.id)
    expect(ids).toContain('config-allow:0')
    expect(ids).toContain('config-deny:0')
    expect(ids).toContain('builtin:0')
    expect(ids.indexOf('config-allow:0')).toBeLessThan(ids.indexOf('config-deny:0'))
    expect(ids.indexOf('config-deny:0')).toBeLessThan(ids.indexOf('builtin:0'))
  })

  it('falls back to the builtin baseline when no project file exists', () => {
    const ws = newWorkspace()
    const config = configWith({ paths: { allow: [], deny: [] } })
    const loaded = loadRuleSet({ config, cwd: ws.dir, platform: 'darwin' })

    expect(loaded.userCount).toBe(0)
    expect(loaded.builtinCount).toBeGreaterThan(10)
    expect(loaded.rules[0]!.id).toBe('builtin:0')
    expect(loaded.rules[0]!.source).toBe('builtin')
  })

  it('assigns stable user ids and sorts by priority', () => {
    const ws = newWorkspace()
    ws.rules(`rules:
  - action: deny
    match:
      paths: ["**/.env"]
  - id: named-allow
    action: allow
    priority: 5
    match:
      paths: ["**/.env.example"]
`)
    const loaded = loadRuleSet({ config: isolatedConfig(), cwd: ws.dir, platform: 'darwin' })

    expect(loaded.userCount).toBe(2)
    expect(loaded.rules.map((rule) => rule.id)).toEqual(['named-allow', 'user:0'])
  })

  it('skips disabled rules without counting them', () => {
    const ws = newWorkspace()
    ws.rules(`rules:
  - id: disabled-rule
    enabled: false
    action: deny
    match:
      paths: ["**/.env"]
`)
    const loaded = loadRuleSet({ config: isolatedConfig(), cwd: ws.dir, platform: 'darwin' })

    expect(loaded.userCount).toBe(0)
    expect(loaded.rules).toHaveLength(0)
  })
})

describe('rule validation', () => {
  it('throws on invalid YAML', () => {
    const config = isolatedConfig('rules-invalid-yaml.yaml')
    expect(() => loadRuleSet({ config, cwd: fixtureDir, platform: 'darwin' })).toThrow(
      /invalid YAML/,
    )
  })

  it('throws on an invalid action', () => {
    const config = isolatedConfig('rules-invalid-shape.yaml')
    expect(() => loadRuleSet({ config, cwd: fixtureDir, platform: 'darwin' })).toThrow(
      /action must be one of/,
    )
  })

  it('throws on an argv block without constraints', () => {
    const ws = newWorkspace()
    ws.rules(`rules:
  - action: deny
    match:
      argv: {}
`)
    expect(() =>
      loadRuleSet({ config: isolatedConfig(), cwd: ws.dir, platform: 'darwin' }),
    ).toThrow(/argv must constrain/)
  })

  it('throws on non-array params patterns', () => {
    const ws = newWorkspace()
    ws.rules(`rules:
  - action: deny
    match:
      params:
        file_path: "**/.env"
`)
    expect(() =>
      loadRuleSet({ config: isolatedConfig(), cwd: ws.dir, platform: 'darwin' }),
    ).toThrow(/non-empty array of strings/)
  })

  it('throws on an unknown platform', () => {
    const ws = newWorkspace()
    ws.rules(`rules:
  - action: deny
    match:
      paths: ["**/.env"]
      when:
        platform: [beos]
`)
    expect(() =>
      loadRuleSet({ config: isolatedConfig(), cwd: ws.dir, platform: 'darwin' }),
    ).toThrow(/unknown platform/)
  })
})

describe('limits and caching', () => {
  it('throws when the compiled rule count exceeds maxRules', () => {
    const ws = newWorkspace()
    ws.rules(`rules:
  - action: deny
    match: { paths: ["**/.env"] }
  - action: deny
    match: { paths: ["**/.ssh/**"] }
  - action: deny
    match: { paths: ["**/.aws/**"] }
`)
    const config = isolatedConfig(undefined, 2)
    expect(() => loadRuleSet({ config, cwd: ws.dir, platform: 'darwin' })).toThrow(
      /rule limit exceeded/,
    )
  })

  it('allows a rule count equal to maxRules', () => {
    const ws = newWorkspace()
    ws.rules(`rules:
  - action: deny
    match: { paths: ["**/.env"] }
  - action: deny
    match: { paths: ["**/.ssh/**"] }
`)
    const loaded = loadRuleSet({
      config: isolatedConfig(undefined, 2),
      cwd: ws.dir,
      platform: 'darwin',
    })
    expect(loaded.userCount).toBe(2)
  })

  it('caches per cwd and invalidates when the rules file changes', () => {
    const ws = newWorkspace()
    const config = isolatedConfig()
    ws.rules(`rules:
  - id: first-rule
    action: deny
    match:
      paths: ["**/.env"]
`)
    const first = loadRuleSet({ config, cwd: ws.dir, platform: 'darwin' })
    expect(loadRuleSet({ config, cwd: ws.dir, platform: 'darwin' })).toBe(first)
    expect(first.userCount).toBe(1)

    ws.rules(`rules:
  - id: first-rule
    action: deny
    match:
      paths: ["**/.env"]
  - id: second-rule
    action: ask
    match:
      paths: ["**/.ssh/**"]
`)
    const second = loadRuleSet({ config, cwd: ws.dir, platform: 'darwin' })
    expect(second).not.toBe(first)
    expect(second.userCount).toBe(2)

    clearPolicyCache()
    expect(loadRuleSet({ config, cwd: ws.dir, platform: 'darwin' })).not.toBe(second)
  })

  it('reloads when the rule config changes for the same cwd', () => {
    const ws = newWorkspace()
    const withoutBuiltin = loadRuleSet({
      config: configWith({
        policy: { builtin: false },
        paths: { allow: [], deny: [] },
      }),
      cwd: ws.dir,
      platform: 'darwin',
    })
    const withBuiltin = loadRuleSet({
      config: configWith({
        policy: { builtin: true },
        paths: { allow: [], deny: [] },
      }),
      cwd: ws.dir,
      platform: 'darwin',
    })

    expect(withoutBuiltin.builtinCount).toBe(0)
    expect(withBuiltin.builtinCount).toBeGreaterThan(10)
  })
})
