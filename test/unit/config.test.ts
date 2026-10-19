import { describe, expect, it } from 'vitest'
import { resolveConfig } from '../../src/config.js'

describe('config', () => {
  it('applies the documented monitor-first defaults', () => {
    const config = resolveConfig()
    expect(config.mode).toBe('monitor')
    expect(config.defaultDecision).toBe('ask')
    expect(config.failClosed).toBe(true)
    expect(config.levels).toEqual({ input: 'aggressive', output: 'balanced' })
    expect(config.redact).toMatchObject({
      userMessages: true,
      toolResults: true,
      systemPrompt: true,
      ptcLog: true,
      notify: false,
    })
    expect(config.paths.deny).toContain('**/.env')
    expect(config.paths.allow).toContain('**/.env.example')
    expect(config.policy.builtin).toBe(true)
    expect(config.audit.enabled).toBe(true)
  })

  it('fills nested defaults without discarding overrides', () => {
    const config = resolveConfig({
      mode: 'enforce',
      levels: { input: 'minimal' },
      audit: { enabled: false },
    })
    expect(config.mode).toBe('enforce')
    expect(config.levels.input).toBe('minimal')
    expect(config.levels.output).toBe('balanced')
    expect(config.audit.enabled).toBe(false)
    expect(config.audit.rotateBytes).toBe(5 * 1024 * 1024)
  })

  it('fails loudly on invalid enums', () => {
    expect(() => resolveConfig({ mode: 'off' })).toThrow()
    expect(() => resolveConfig({ levels: { input: 'maximum' } })).toThrow()
  })
})
