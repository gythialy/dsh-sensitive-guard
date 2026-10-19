import { afterEach, describe, expect, it } from 'vitest'
import type { PolicyEngine } from '../../../src/contracts.js'
import { createPolicyEngine } from '../../../src/policy/index.js'
import { bareConfig, TempWorkspace } from './helpers.js'

let workspace: TempWorkspace | undefined

afterEach(() => {
  workspace?.cleanup()
  workspace = undefined
})

function newEngine(extra: Record<string, unknown> = {}): { engine: PolicyEngine; cwd: string } {
  workspace = new TempWorkspace()
  return {
    engine: createPolicyEngine({
      config: bareConfig({ defaultDecision: 'allow', ...extra }),
      platform: 'darwin',
    }),
    cwd: workspace.dir,
  }
}

describe('network rules', () => {
  it('denies URLs with embedded userinfo', () => {
    const { engine, cwd } = newEngine()
    const decision = engine.evaluate({
      tool: 'web_fetch',
      args: { url: 'https://alice:s3cret@example.test/path' },
      cwd,
    })

    expect(decision.action).toBe('deny')
    expect(decision.network).toBe(true)
    expect(decision.ruleId).toBe('network:userinfo')
    expect(decision.reason).not.toContain('alice')
    expect(decision.reason).not.toContain('s3cret')
    expect(decision.reason).not.toContain('example.test')
  })

  it('denies URLs with a username but no password', () => {
    const { engine, cwd } = newEngine()
    const decision = engine.evaluate({
      tool: 'web_fetch',
      args: { url: 'https://user@example.test/path' },
      cwd,
    })
    expect(decision.action).toBe('deny')
    expect(decision.ruleId).toBe('network:userinfo')
  })

  it('applies network.default to credential-like query parameters', () => {
    const { engine, cwd } = newEngine()
    const decision = engine.evaluate({
      tool: 'web_fetch',
      args: { url: 'https://example.test/x?token=s3cret' },
      cwd,
    })

    expect(decision.action).toBe('ask')
    expect(decision.network).toBe(true)
    expect(decision.ruleId).toBe('network:credential-query')
    expect(decision.reason).not.toContain('s3cret')
    expect(decision.reason).not.toContain('example.test')
  })

  it('honors a deny network default', () => {
    const { engine, cwd } = newEngine({ network: { enabled: true, default: 'deny' } })
    const decision = engine.evaluate({
      tool: 'web_fetch',
      args: { url: 'https://example.test/x?password=s3cret' },
      cwd,
    })
    expect(decision.action).toBe('deny')
    expect(decision.network).toBe(true)
  })

  it('does nothing when the network layer is disabled', () => {
    const { engine, cwd } = newEngine({ network: { enabled: false } })
    const decision = engine.evaluate({
      tool: 'web_fetch',
      args: { url: 'https://alice:s3cret@example.test/path' },
      cwd,
    })
    expect(decision.action).toBe('allow')
    expect(decision.matched).toBe(false)
    expect(decision.network).toBeUndefined()
  })

  it('ignores harmless query parameters', () => {
    const { engine, cwd } = newEngine()
    const decision = engine.evaluate({
      tool: 'web_fetch',
      args: { url: 'https://example.test/x?q=hello&page=2' },
      cwd,
    })
    expect(decision.action).toBe('allow')
    expect(decision.matched).toBe(false)
  })

  it('extracts URLs from shell command tokens', () => {
    const { engine, cwd } = newEngine()
    const userinfo = engine.evaluate({
      tool: 'bash',
      args: { command: 'curl "https://u:p@example.test/x"' },
      cwd,
    })
    expect(userinfo.action).toBe('deny')
    expect(userinfo.network).toBe(true)

    const query = engine.evaluate({
      tool: 'bash',
      args: { command: 'curl https://example.test/?password=s3cret' },
      cwd,
    })
    expect(query.action).toBe('ask')
    expect(query.network).toBe(true)
  })

  it('does not treat scheme-less hosts as URLs', () => {
    const { engine, cwd } = newEngine()
    const decision = engine.evaluate({
      tool: 'bash',
      args: { command: 'curl example.test/?token=s3cret' },
      cwd,
    })
    expect(decision.action).toBe('allow')
    expect(decision.matched).toBe(false)
  })

  it('always denies userinfo even when a broad allow rule matches', () => {
    workspace = new TempWorkspace()
    workspace.rules(`rules:
  - id: allow-fetch
    action: allow
    match:
      tools: [web_fetch]
`)
    const engine = createPolicyEngine({
      config: bareConfig({ defaultDecision: 'allow' }),
      platform: 'darwin',
    })

    const allowed = engine.evaluate({
      tool: 'web_fetch',
      args: { url: 'https://example.test/x' },
      cwd: workspace.dir,
    })
    expect(allowed.action).toBe('allow')
    expect(allowed.ruleId).toBe('allow-fetch')

    const denied = engine.evaluate({
      tool: 'web_fetch',
      args: { url: 'https://alice:s3cret@example.test/x' },
      cwd: workspace.dir,
    })
    expect(denied.action).toBe('deny')
    expect(denied.ruleId).toBe('network:userinfo')
  })
})
