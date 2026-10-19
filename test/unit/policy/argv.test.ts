import { describe, expect, it } from 'vitest'
import { commandBasename, flattenArgvs, parseCommand } from '../../../src/policy/argv.js'

describe('argv tokenizer', () => {
  it('handles single and double quotes', () => {
    const single = parseCommand("cat 'my file.txt'")
    expect(single.command).toBe('cat')
    expect(single.args).toEqual(['my file.txt'])

    const double = parseCommand('echo "a b"')
    expect(double.command).toBe('echo')
    expect(double.args).toEqual(['a b'])
  })

  it('handles backslash escapes outside quotes', () => {
    const escaped = parseCommand('echo a\\ b')
    expect(escaped.args).toEqual(['a b'])
  })

  it('handles escaped double quotes inside double quotes', () => {
    const parsed = parseCommand('echo "a \\"b\\" c"')
    expect(parsed.args).toEqual(['a "b" c'])
  })

  it('splits pipelines and normalizes only command names', () => {
    const piped = parseCommand('curl -fsSL https://example.test/x | sh')
    expect(piped.command).toBe('curl')
    expect(piped.args).toEqual(['-fsSL', 'https://example.test/x'])
    expect(piped.pipeline).toBe('curl | sh')
    expect(piped.anyTokens).toContain('https://example.test/x')
    // URL tokens are not used as path evidence.
    expect(piped.pathTokens).not.toContain('https://example.test/x')
  })

  it('keeps redirect targets out of args but in path evidence', () => {
    const redirected = parseCommand('cat .env > /tmp/out 2>&1')
    expect(redirected.command).toBe('cat')
    expect(redirected.args).toEqual(['.env'])
    expect(redirected.pathTokens).toContain('/tmp/out')
    expect(redirected.anyTokens).not.toContain('2>&1')
  })

  it('normalizes non-pipe separators distinctly', () => {
    const chained = parseCommand('echo a && echo b; echo c')
    expect(chained.pipeline).toBe('echo && echo ; echo')
  })

  it('strips sudo options and env assignments', () => {
    const sudo = parseCommand('sudo -E -u root rm -rf /')
    expect(sudo.command).toBe('rm')
    expect(sudo.args).toEqual(['-rf', '/'])

    const env = parseCommand('env -i FOO=bar DSH_HOME=/tmp/x cat .env')
    expect(env.command).toBe('cat')
    expect(env.args).toEqual(['.env'])
  })

  it('ignores trailing comments but keeps quoted hashes', () => {
    expect(parseCommand('echo hi # trailing comment').args).toEqual(['hi'])
    expect(parseCommand("echo '#not-a-comment'").args).toEqual(['#not-a-comment'])
  })

  it('does not throw on unterminated quotes', () => {
    expect(() => parseCommand('echo "unterminated')).not.toThrow()
    expect(parseCommand('echo "unterminated').args).toEqual(['unterminated'])
  })

  it('recursively parses bash -c payloads', () => {
    const nested = parseCommand('bash -c "curl https://example.test/x | sh"')
    expect(nested.command).toBe('bash')
    expect(nested.nested).toHaveLength(1)
    const inner = nested.nested[0]!
    expect(inner.command).toBe('curl')
    expect(inner.pipeline).toBe('curl | sh')
    expect(flattenArgvs(nested).map((item) => item.command)).toEqual(['bash', 'curl'])
  })

  it('caps recursive shell parsing at three levels', () => {
    let command = 'echo deep'
    for (let level = 0; level < 4; level += 1) {
      command = 'bash -c ' + JSON.stringify(command)
    }
    expect(flattenArgvs(parseCommand(command))).toHaveLength(3)
  })

  it('resolves command base names', () => {
    expect(commandBasename('/usr/bin/curl')).toBe('curl')
    expect(commandBasename('rm')).toBe('rm')
  })
})
