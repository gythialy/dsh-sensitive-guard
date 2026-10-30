import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { resetSecretPlaceholderState } from '../../../src/redact/index.js'
import { containedInRanges, findUrlPathRanges } from '../../../src/redact/urls.js'
import { SAMPLE } from '../../fixtures/redact/samples.js'
import { cleanupTempDirs, redactorFor } from './helpers.js'

afterEach(cleanupTempDirs)
beforeEach(() => resetSecretPlaceholderState())

/**
 * Expected path range for the first occurrence of `path` inside `text`. The
 * helper is fed the path without its leading `/`, matching what the scanner
 * reports.
 */
function rangeOf(text: string, path: string, from = 0): [number, number] {
  const start = text.indexOf(path, from)
  expect(start).toBeGreaterThanOrEqual(0)
  return [start, start + path.length]
}

describe('findUrlPathRanges', () => {
  it('returns nothing without a scheme', () => {
    expect(findUrlPathRanges('/alpha/beta.html')).toEqual([])
    expect(findUrlPathRanges('no links here')).toEqual([])
  })

  it('covers the path of one absolute URL', () => {
    const text = 'see https://example.com/alpha/beta.html now'
    expect(findUrlPathRanges(text)).toEqual([rangeOf(text, 'alpha/beta.html')])
  })

  it('stops at the query string and the fragment', () => {
    const query = 'https://example.com/alpha?x=1'
    expect(findUrlPathRanges(query)).toEqual([rangeOf(query, 'alpha')])

    const fragment = 'https://example.com/alpha#section'
    expect(findUrlPathRanges(fragment)).toEqual([rangeOf(fragment, 'alpha')])
  })

  it('contributes nothing when the URL has no path', () => {
    expect(findUrlPathRanges('https://example.com')).toEqual([])
    expect(findUrlPathRanges('https://example.com?x=1')).toEqual([])
    expect(findUrlPathRanges('https://example.com#top')).toEqual([])
    expect(findUrlPathRanges('https://example.com/')).toEqual([])
  })

  it('skips the userinfo and the port when locating the path', () => {
    const text = 'https://svc:secret@example.com:8443/path/one?z=1'
    expect(findUrlPathRanges(text)).toEqual([rangeOf(text, 'path/one')])
  })

  it('handles the uppercase scheme and several URLs in prose', () => {
    const upper = 'HTTPS://EXAMPLE.COM/PATH/ONE'
    expect(findUrlPathRanges(upper)).toEqual([rangeOf(upper, 'PATH/ONE')])
    const prose = 'link http://example.com/alpha and https://example.com/beta here'
    expect(findUrlPathRanges(prose)).toEqual([rangeOf(prose, 'alpha'), rangeOf(prose, 'beta')])
  })

  it('returns every URL in order', () => {
    const text = 'a https://one.example.com/alpha b http://two.example.com/beta/gamma c'
    const ranges = findUrlPathRanges(text)
    expect(ranges).toEqual([rangeOf(text, 'alpha'), rangeOf(text, 'beta/gamma')])
    expect(ranges[0]?.[0] ?? -1).toBeLessThan(ranges[1]?.[0] ?? -1)
  })

  it('keeps percent-encoded paths inside the range', () => {
    const text = 'https://example.com/%E4%B8%AD%E6%96%87/path'
    expect(findUrlPathRanges(text)).toEqual([rangeOf(text, '%E4%B8%AD%E6%96%87/path')])
  })
})

describe('containedInRanges', () => {
  const ranges = [
    [10, 20],
    [30, 40],
  ] as const

  it('accepts a fully contained span, including exact bounds', () => {
    expect(containedInRanges(ranges, 12, 18)).toBe(true)
    expect(containedInRanges(ranges, 10, 20)).toBe(true)
    expect(containedInRanges(ranges, 35, 40)).toBe(true)
  })

  it('rejects partial overlap, gaps, and out-of-range spans', () => {
    expect(containedInRanges(ranges, 8, 12)).toBe(false)
    expect(containedInRanges(ranges, 18, 22)).toBe(false)
    expect(containedInRanges(ranges, 22, 28)).toBe(false)
    expect(containedInRanges(ranges, 41, 44)).toBe(false)
    expect(containedInRanges([], 0, 1)).toBe(false)
  })
})

describe('URL path context', () => {
  it('leaves a URL whose path carries a hex row id unchanged', () => {
    const redactor = redactorFor('aggressive')
    const result = redactor.redactText(SAMPLE.urlWithHexPathId, 'aggressive')
    expect(result.changed).toBe(false)
    expect(result.text).toBe(SAMPLE.urlWithHexPathId)
    expect(result.hits).toEqual([])
    expect(redactor.scan(SAMPLE.urlWithHexPathId, 'aggressive')).toBe(false)
  })

  it('still redacts the entropy fallback in a query string', () => {
    const text = `https://example.com/download?sig=${SAMPLE.highEntropy}`
    const result = redactorFor('aggressive').redactText(text, 'aggressive')
    expect(result.changed).toBe(true)
    expect(result.hits.map((hit) => hit.category)).toEqual(['high-entropy'])
  })

  it('still redacts the entropy fallback in a fragment', () => {
    const text = `https://example.com/download#${SAMPLE.highEntropy}`
    const result = redactorFor('aggressive').redactText(text, 'aggressive')
    expect(result.changed).toBe(true)
    expect(result.hits.map((hit) => hit.category)).toEqual(['high-entropy'])
  })

  it('still redacts a provider token inside the path', () => {
    const text = `https://example.com/k/${SAMPLE.githubToken}`
    const result = redactorFor('aggressive').redactText(text, 'aggressive')
    expect(result.changed).toBe(true)
    expect(result.hits.map((hit) => hit.category)).toEqual(['github-token'])
  })

  it('still redacts PII inside the path (only the entropy fallback is exempt)', () => {
    const text = `https://example.com/i/${SAMPLE.idCn}`
    const result = redactorFor('aggressive').redactText(text, 'aggressive')
    expect(result.changed).toBe(true)
    expect(result.hits.map((hit) => hit.category)).toEqual(['id-cn'])
  })

  it('keeps the fallback active for tokens without URL context', () => {
    const result = redactorFor('aggressive').redactText(SAMPLE.highEntropy, 'aggressive')
    expect(result.changed).toBe(true)
    expect(result.hits.map((hit) => hit.category)).toEqual(['high-entropy'])
  })
})
