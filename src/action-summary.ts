/**
 * Build one short, redacted action summary for the approval prompt. Secrets are
 * replaced with placeholders and URL userinfo/query values are removed before
 * the string reaches displayReason.
 * @module dsh-sensitive-guard/action-summary
 */
import type { Redactor } from './contracts.js'
import { cleanAction, type LocalizedAction } from './messages.js'

const URL_PATTERN = /https?:\/\/[^\s"']+/g

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

function stringField(record: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = record[key]
    if (typeof value === 'string' && value.trim().length > 0) return value
  }
  return undefined
}

function compact(value: unknown): string | undefined {
  try {
    const text = JSON.stringify(value)
    if (text === undefined || text.length === 0 || text === '{}') return undefined
    return text
  } catch {
    return undefined
  }
}

function sanitizeUrl(raw: string): string {
  try {
    const url = new URL(raw)
    url.username = ''
    url.password = ''
    for (const key of url.searchParams.keys()) url.searchParams.set(key, '***')
    return url.toString()
  } catch {
    return raw
  }
}

function pathVerb(tool: string): LocalizedAction {
  switch (tool) {
    case 'read':
    case 'read_file':
      return { en: 'read', zh: '读取' }
    case 'write':
    case 'write_file':
      return { en: 'write', zh: '写入' }
    case 'edit':
    case 'edit_file':
      return { en: 'edit', zh: '编辑' }
    default:
      return { en: 'access', zh: '访问' }
  }
}

/**
 * Summarize the concrete operation: shell command, URL, path, or compact JSON.
 * The caller decides whether to display it; deny reasons never receive it.
 */
export function summarizeAction(
  tool: string,
  args: unknown,
  redactor: Redactor,
): LocalizedAction | undefined {
  if (args === undefined || args === null) return undefined

  const record = asRecord(args)
  let raw: string | undefined
  let kind: 'command' | 'url' | 'path' | 'generic' = 'generic'

  if (record !== undefined) {
    const command = stringField(record, ['command'])
    const url = stringField(record, ['url'])
    const path = stringField(record, [
      'file_path',
      'path',
      'target',
      'file',
      'notebook_path',
      'directory',
    ])
    if (command !== undefined) {
      raw = command
      kind = 'command'
    } else if (url !== undefined) {
      raw = sanitizeUrl(url)
      kind = 'url'
    } else if (path !== undefined) {
      raw = path
      kind = 'path'
    } else {
      raw = compact(record)
    }
  } else if (typeof args === 'string') {
    raw = args
  } else {
    raw = compact(args)
  }

  if (raw === undefined || raw.trim().length === 0) return undefined
  const withoutUrls = raw.replace(URL_PATTERN, (match) => sanitizeUrl(match))
  const redacted = cleanAction(redactor.redactText(withoutUrls, 'balanced').text)
  if (redacted === undefined) return undefined
  if (kind === 'command') return { en: redacted, zh: redacted }

  const verb =
    kind === 'url'
      ? { en: 'fetch', zh: '请求' }
      : kind === 'path'
        ? pathVerb(tool)
        : { en: 'call', zh: '调用' }
  return {
    en: cleanAction(verb.en + ' ' + redacted) ?? redacted,
    zh: cleanAction(verb.zh + ' ' + redacted) ?? redacted,
  }
}
