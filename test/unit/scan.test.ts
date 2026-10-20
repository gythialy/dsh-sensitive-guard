import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { scanPaths } from '../../src/cli/scan.js'

const dirs: string[] = []
const AWS_KEY = 'AKIA' + '1234567890' + 'ABCDEF'

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sg-scan-'))
  dirs.push(dir)
  return dir
}

function options(dir: string, overrides: Partial<Parameters<typeof scanPaths>[0]> = {}) {
  return {
    cwd: dir,
    maxBytes: 1024 * 1024,
    json: false,
    staged: false,
    exitCode: true,
    paths: [dir],
    ...overrides,
  }
}

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

describe('scan CLI', () => {
  it('reports categories and line numbers without the matched value', async () => {
    const dir = await tempDir()
    await writeFile(
      path.join(dir, 'config.txt'),
      'safe\naws=' + AWS_KEY + '\nmail=alice@example.com\n',
    )

    const result = await scanPaths(options(dir))
    expect(result.scannedFiles).toBe(1)
    const categories = result.findings.map((finding) => finding.category)
    expect(categories).toContain('aws-access-key')
    expect(categories).toContain('email')
    const aws = result.findings.find((finding) => finding.category === 'aws-access-key')
    expect(aws?.file).toBe('config.txt')
    expect(aws?.line).toBe(2)
    expect(JSON.stringify(result)).not.toContain(AWS_KEY)
    expect(JSON.stringify(result)).not.toContain('alice@example.com')
  })

  it('returns no findings for clean text', async () => {
    const dir = await tempDir()
    await writeFile(path.join(dir, 'README.md'), 'ordinary documentation text\n')
    const result = await scanPaths(options(dir))
    expect(result.findings).toEqual([])
    expect(result.scannedFiles).toBe(1)
  })

  it('skips binary and oversized files', async () => {
    const dir = await tempDir()
    await writeFile(path.join(dir, 'binary.bin'), Buffer.from([0, 1, 2, 3, 0, 5]))
    await writeFile(path.join(dir, 'large.txt'), 'a'.repeat(2048))
    const result = await scanPaths(options(dir, { maxBytes: 1024 }))
    expect(result.skippedFiles).toBe(2)
    expect(result.findings).toEqual([])
  })

  it('walks directories but skips dependency/build trees', async () => {
    const dir = await tempDir()
    await writeFile(path.join(dir, 'src.txt'), AWS_KEY)
    await writeFile(path.join(dir, 'node_modules-ignore'), '')
    const nested = path.join(dir, 'node_modules')
    await writeFile(path.join(dir, 'nested-placeholder'), '')
    await rm(path.join(dir, 'nested-placeholder'))
    const { mkdir } = await import('node:fs/promises')
    await mkdir(nested)
    await writeFile(path.join(nested, 'leak.txt'), 'sk-ant-' + 'A'.repeat(40))

    const result = await scanPaths(options(dir))
    expect(result.findings.some((finding) => finding.file === 'src.txt')).toBe(true)
    expect(result.findings.some((finding) => finding.file.includes('node_modules'))).toBe(false)
  })

  it('accepts --max-bytes and rejects invalid usage in main', async () => {
    const { main } = await import('../../src/cli/scan.js')
    expect(await main(['--help'])).toBe(0)
    expect(await main(['--max-bytes', 'not-a-number'])).toBe(2)
    expect(await main(['--unknown'])).toBe(2)
  })
})
