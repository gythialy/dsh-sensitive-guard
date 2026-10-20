/**
 * Host-side locale resolution. DSH stores the explicit language preference in
 * the `locale` settings entry; browser-only language detection is not visible
 * to host plugins, so an absent preference falls back to the process locale.
 * @module dsh-sensitive-guard/locale
 */
import type { Context } from '@deepseek-ai/cordis'

/** Languages with a complete guard message catalog. */
export type GuardLocale = 'en' | 'zh'

interface LocaleEntry {
  ns: string
  value?: { preference?: unknown }
}

interface SettingsLike {
  describe(): LocaleEntry[]
}

/** Normalize a BCP 47-style tag to a supported catalog; unsupported -> English. */
export function normalizeLocale(value: unknown): GuardLocale {
  if (typeof value !== 'string') return 'en'
  return /^zh(?:[-_]|$)/i.test(value.trim()) ? 'zh' : 'en'
}

/**
 * Read the active DSH language without requiring the settings service to be
 * present. The fallback chain is explicit preference, process locale, English.
 */
export function localeFromSettings(ctx: Context): GuardLocale {
  try {
    const settings = ctx.get('settings') as SettingsLike | undefined
    if (settings !== undefined) {
      const entry = settings.describe().find((candidate) => candidate.ns === 'locale')
      const preference = entry?.value?.preference
      if (typeof preference === 'string' && preference.length > 0) {
        return normalizeLocale(preference)
      }
    }
  } catch {
    // Settings may not be ready yet, or this profile may omit the service.
  }
  return normalizeLocale(process.env.LC_ALL ?? process.env.LC_MESSAGES ?? process.env.LANG)
}
