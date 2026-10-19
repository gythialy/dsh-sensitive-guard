import { describe, expect, it } from 'vitest'
import { compileGlob, escapeLiteralGlobSyntax } from '../../../src/policy/glob.js'

const options = { platform: 'darwin' as NodeJS.Platform }

describe('literal shell syntax in globs', () => {
  it('matches the fork-bomb signature literally', () => {
    const matcher = compileGlob('*:(){ :|:& };:*', options)
    expect(matcher(':(){ :|:& };:')).toBe(true)
    expect(matcher('echo safe')).toBe(false)
  })

  it('matches a pipeline signature instead of treating | as alternation', () => {
    const matcher = compileGlob('curl*|*sh', options)
    expect(matcher('curl | sh')).toBe(true)
    expect(matcher('wget https://x | bash')).toBe(false)
    expect(matcher('printf hello | sh')).toBe(false)
  })

  it('preserves escapes and normal glob operators', () => {
    expect(escapeLiteralGlobSyntax('a\\(b')).toBe('a\\(b')
    expect(compileGlob('*.{pem,key}', options)('server.pem')).toBe(true)
    expect(compileGlob('**/.env', options)('/Users/example/.env')).toBe(true)
  })
})
