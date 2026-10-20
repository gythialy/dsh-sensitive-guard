import { describe, expect, it } from 'vitest'
import {
  createEgressPolicy,
  normalizeEgressHost,
  parseEgressAuthority,
  parseEgressEntry,
  type EgressPolicyOptions,
} from '../../../src/egress/policy.js'

function policy(overrides: Partial<EgressPolicyOptions> = {}) {
  return createEgressPolicy({ allow: [], deny: [], unknown: 'allow', ...overrides })
}

describe('egress policy entries', () => {
  it('normalizes host case, trailing root dot, and IPv6 brackets', () => {
    expect(normalizeEgressHost('API.Example.COM.')).toBe('api.example.com')
    expect(normalizeEgressHost('[::1]')).toBe('::1')
    expect(normalizeEgressHost(' bad host ')).toBeUndefined()
    expect(normalizeEgressHost('user@host')).toBeUndefined()
    expect(normalizeEgressHost('')).toBeUndefined()
  })

  it('parses host, host:port, glob, and bracketed IPv6 entries', () => {
    expect(parseEgressEntry('example.com')?.port).toBeUndefined()
    expect(parseEgressEntry('example.com:8443')?.port).toBe(8443)
    expect(parseEgressEntry('*.corp.example')?.host).toBe('*.corp.example')
    expect(parseEgressEntry('[::1]:443')?.host).toBe('::1')
    expect(parseEgressEntry('[::1]:443')?.port).toBe(443)
  })

  it('drops unparseable entries instead of matching them loosely', () => {
    expect(parseEgressEntry('')).toBeUndefined()
    expect(parseEgressEntry('   ')).toBeUndefined()
    expect(parseEgressEntry('example.com:0')).toBeUndefined()
    expect(parseEgressEntry('example.com:70000')).toBeUndefined()
    expect(parseEgressEntry('example.com:abc')).toBeUndefined()
    expect(parseEgressEntry('::1:443')).toBeUndefined()
  })

  it('parses CONNECT authorities and refuses a missing port', () => {
    expect(parseEgressAuthority('example.com:443')).toEqual({ host: 'example.com', port: 443 })
    expect(parseEgressAuthority('[::1]:443')).toEqual({ host: '::1', port: 443 })
    expect(parseEgressAuthority('example.com')).toBeUndefined()
    expect(parseEgressAuthority('example.com:0')).toBeUndefined()
    expect(parseEgressAuthority('')).toBeUndefined()
  })
})

describe('egress policy evaluation', () => {
  it('matches a bare host on every port and a host:port entry on one port', () => {
    const guard = policy({ allow: ['example.com', 'api.corp:8443'] })
    expect(guard.evaluate({ host: 'example.com', port: 443 })).toMatchObject({
      action: 'allow',
      matched: true,
      reason: 'allow-list',
      rule: 'egress-allow[0]',
    })
    expect(guard.evaluate({ host: 'api.corp', port: 8443 }).action).toBe('allow')
    expect(guard.evaluate({ host: 'api.corp', port: 443 }).action).toBe('allow')
  })

  it('lets deny entries win over a broader allow entry', () => {
    const guard = policy({ allow: ['*.example.com'], deny: ['secrets.example.com'] })
    expect(guard.evaluate({ host: 'api.example.com', port: 443 }).action).toBe('allow')
    expect(guard.evaluate({ host: 'secrets.example.com', port: 443 })).toMatchObject({
      action: 'deny',
      matched: true,
      reason: 'deny-list',
      rule: 'egress-deny[0]',
    })
  })

  it('applies the configured default to unmatched destinations', () => {
    expect(policy({ unknown: 'allow' }).evaluate({ host: 'new.example', port: 443 })).toMatchObject(
      {
        action: 'allow',
        matched: false,
        reason: 'unknown-allow',
      },
    )
    expect(policy({ unknown: 'deny' }).evaluate({ host: 'new.example', port: 443 })).toMatchObject({
      action: 'deny',
      matched: false,
      reason: 'unknown-deny',
    })
  })

  it('refuses invalid destinations regardless of the unknown default', () => {
    expect(policy({ unknown: 'allow' }).evaluate({ host: '', port: 443 })).toMatchObject({
      action: 'deny',
      reason: 'invalid-target',
    })
    expect(policy({ unknown: 'allow' }).evaluate({ host: 'ok.example', port: 0 }).reason).toBe(
      'invalid-target',
    )
    expect(policy({ unknown: 'allow' }).evaluate({ host: 'ok.example', port: 65_536 }).reason).toBe(
      'invalid-target',
    )
  })

  it('reports compiled counts and the unknown default', () => {
    const guard = policy({ allow: ['a.example', 'b.example'], deny: ['c.example', ''] })
    expect(guard.allowCount).toBe(2)
    expect(guard.denyCount).toBe(1)
    expect(guard.ruleCount).toBe(3)
    expect(guard.unknown).toBe('allow')
  })

  it('matches bracketed IPv6 destinations', () => {
    const guard = policy({ deny: ['[::1]:443'] })
    expect(guard.evaluate({ host: '::1', port: 443 }).action).toBe('deny')
    expect(guard.evaluate({ host: '::1', port: 8443 }).action).toBe('allow')
  })
})
