import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { compileGlob } from '../../../src/policy/glob.js'
import { expandHome, expandPathString, pathCandidates } from '../../../src/policy/paths.js'

const IS_WINDOWS = process.platform === 'win32'

describe('glob compilation', () => {
  it('matches dotfiles and keeps example suffixes distinct', () => {
    const matcher = compileGlob('**/.env', { platform: 'darwin' })
    expect(matcher('/tmp/project/.env')).toBe(true)
    expect(matcher('/tmp/project/.env.example')).toBe(false)
  })

  it('rejects empty and overlong patterns', () => {
    expect(() => compileGlob('', { platform: 'darwin' })).toThrow(/empty glob/)
    expect(() => compileGlob('a'.repeat(513), { platform: 'darwin' })).toThrow(/512/)
  })

  it('is case-insensitive on win32 only', () => {
    expect(compileGlob('**/.ENV', { platform: 'win32' })('C:/work/.env')).toBe(true)
    expect(compileGlob('**/.ENV', { platform: 'darwin' })('/work/.env')).toBe(false)
  })
})

describe('path expansion', () => {
  const env = {
    HOME: '/home/tester',
    DSH_HOME: '/home/tester/.dsh',
    USER: 'tester',
    PWD: '/work',
  }

  it('expands home and whitelisted variables', () => {
    expect(expandHome('~/.ssh/id_rsa', env)).toBe('/home/tester/.ssh/id_rsa')
    expect(expandPathString('$DSH_HOME/rules.yaml', env)).toBe('/home/tester/.dsh/rules.yaml')
    expect(expandPathString('${HOME}/keys', env)).toBe('/home/tester/keys')
  })

  it('leaves unknown variables untouched', () => {
    expect(expandPathString('$UNKNOWN/x', env)).toBe('$UNKNOWN/x')
  })
})

describe('path candidates', () => {
  const env = { HOME: '/home/tester', DSH_HOME: '/home/tester/.dsh' }
  const cwd = '/work/project'

  it('includes absolute and cwd-relative forms', () => {
    const candidates = pathCandidates('.env', { cwd, platform: 'darwin', env })
    expect(candidates).toContain('/work/project/.env')
    expect(candidates).toContain('.env')
  })

  it('expands home and whitelisted variables before resolving', () => {
    expect(pathCandidates('~/keys/id_rsa', { cwd, platform: 'darwin', env })).toContain(
      '/home/tester/keys/id_rsa',
    )
    expect(pathCandidates('$DSH_HOME/x', { cwd, platform: 'darwin', env })).toContain(
      '/home/tester/.dsh/x',
    )
  })

  it('normalizes Windows separators to forward slashes', () => {
    const backslash = String.fromCharCode(92)
    const winPath = ['C:', 'Users', 'tester', 'keys', 'id_rsa'].join(backslash)
    const candidates = pathCandidates(winPath, { cwd: 'C:/work', platform: 'win32', env: {} })
    expect(candidates).toContain('C:/Users/tester/keys/id_rsa')
  })

  it.skipIf(IS_WINDOWS)('includes the realpath of a symlinked path', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'sg-policy-links-'))
    try {
      const privateDir = path.join(dir, 'private')
      mkdirSync(privateDir)
      writeFileSync(path.join(privateDir, 'id_rsa'), 'synthetic')
      const alias = path.join(dir, 'alias')
      symlinkSync(privateDir, alias, 'dir')

      const realPrivate = realpathSync(privateDir)
      const candidates = pathCandidates(path.join(alias, 'id_rsa'), {
        cwd: dir,
        platform: process.platform,
      })
      expect(candidates).toContain(realPrivate + '/id_rsa')
      expect(candidates).toContain('alias/id_rsa')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
