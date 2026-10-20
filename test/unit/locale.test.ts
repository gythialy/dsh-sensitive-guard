import type { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { localeFromSettings, normalizeLocale } from '../../src/locale.js'

function contextWith(preference: unknown): Context {
  return {
    get(name: string) {
      if (name !== 'settings') return undefined
      return {
        describe: () => [{ ns: 'locale', value: preference === undefined ? {} : { preference } }],
      }
    },
  } as unknown as Context
}

afterEach(() => {
  vi.unstubAllEnvs()
})

describe('locale resolution', () => {
  it('normalizes supported tags and falls back to English', () => {
    expect(normalizeLocale('zh')).toBe('zh')
    expect(normalizeLocale('zh-CN')).toBe('zh')
    expect(normalizeLocale('zh-Hans')).toBe('zh')
    expect(normalizeLocale('en-US')).toBe('en')
    expect(normalizeLocale('fr')).toBe('en')
    expect(normalizeLocale(undefined)).toBe('en')
  })

  it('reads the DSH locale preference from the settings service', () => {
    expect(localeFromSettings(contextWith('zh-CN'))).toBe('zh')
    expect(localeFromSettings(contextWith('en'))).toBe('en')
  })

  it('falls back to the process locale when settings are unavailable', () => {
    vi.stubEnv('LC_ALL', 'zh_CN.UTF-8')
    vi.stubEnv('LC_MESSAGES', '')
    vi.stubEnv('LANG', '')
    expect(localeFromSettings({} as Context)).toBe('zh')

    vi.stubEnv('LC_ALL', '')
    vi.stubEnv('LANG', 'en_US.UTF-8')
    expect(localeFromSettings({} as Context)).toBe('en')
  })

  it('survives a settings service that is not ready', () => {
    vi.stubEnv('LC_ALL', '')
    vi.stubEnv('LC_MESSAGES', '')
    vi.stubEnv('LANG', 'en_US.UTF-8')
    const broken = {
      get() {
        throw new Error('settings not ready')
      },
    } as unknown as Context
    expect(localeFromSettings(broken)).toBe('en')
  })
})
