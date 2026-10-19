import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type { ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { resolveConfig } from '../../src/config.js'
import { apply } from '../../src/index.js'
import type { GuardConfig } from '../../src/config.js'
import { createFakeContext, type FakeContext } from '../helpers/fake-ctx.js'

const AWS_KEY = 'AKIA' + '1234567890' + 'ABCDEF'
const ANTHROPIC_KEY = 'sk-ant-' + 'A'.repeat(40)
const EMAIL = 'alice@example.com'

let dir: string
let auditPath: string
let keyPath: string

beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'sg-hooks-'))
  auditPath = path.join(dir, 'audit.jsonl')
  keyPath = path.join(dir, 'pii.key')
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

function config(overrides: Partial<GuardConfig> = {}): GuardConfig {
  return resolveConfig({
    mode: 'enforce',
    defaultDecision: 'allow',
    pii: { enabled: true, keyFile: keyPath, restore: false },
    audit: { enabled: true, path: auditPath, rotateBytes: 1024 * 1024 },
    ...overrides,
  })
}

function start(overrides: Partial<GuardConfig> = {}): FakeContext {
  const fake = createFakeContext()
  apply(fake.ctx, config(overrides))
  return fake
}

function makeAgent(cwd: string): Agent {
  return {
    session: { id: 'session-1', header: { cwd } },
  } as unknown as Agent
}

function makeExec(name: string, args: unknown, cwd = dir): ToolExecution {
  return {
    callId: 'call-1',
    rootCallId: 'call-1',
    name,
    arguments: args,
    agent: makeAgent(cwd),
    signal: new AbortController().signal,
    token: Symbol('token'),
  } as unknown as ToolExecution
}

function makeResult(content: string, value?: unknown, isError = false): ToolExecutionResult {
  if (isError) {
    return {
      isError: true,
      error: { message: 'failed' },
      content: [{ type: 'text', text: content }],
    } as unknown as ToolExecutionResult
  }
  return {
    isError: false,
    value: (value ?? null) as never,
    content: [{ type: 'text', text: content }],
  } as unknown as ToolExecutionResult
}

interface RewrittenMessage {
  id?: string
  role?: string
  content: Array<{ type: string; text?: string }>
}

async function readAudit(): Promise<Array<Record<string, unknown>>> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      const text = await readFile(auditPath, 'utf8')
      if (text.trim().length > 0) {
        return text
          .trim()
          .split('\n')
          .map((line) => JSON.parse(line) as Record<string, unknown>)
      }
    } catch {
      // Not created yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  return []
}

describe('hook integration', () => {
  it('redacts user messages before the step commits them', async () => {
    const fake = start()
    const listener = fake.listener('agent/pre-step')
    const messages = [
      {
        id: 'm1',
        role: 'user',
        source: { kind: 'user' },
        content: [{ type: 'text', text: `key=${ANTHROPIC_KEY} mail=${EMAIL}` }],
      },
    ]
    const next = vi.fn(async () => ({ kind: 'enter', messages }))

    const decision = (await listener(
      { agent: makeAgent(dir), messages, turn: 1, step: 1, signal: new AbortController().signal },
      next,
    )) as { kind: string; messages: RewrittenMessage[] }

    expect(decision.kind).toBe('enter')
    expect(decision.messages[0]!.id).toBe('m1')
    expect(decision.messages[0]!.role).toBe('user')
    const text = decision.messages[0]!.content[0]!.text ?? ''
    expect(text).toContain('[SECRET:anthropic-key:')
    expect(text).toContain('[[PII_EMAIL_')
    expect(text).not.toContain(ANTHROPIC_KEY)
    expect(text).not.toContain(EMAIL)
  })

  it('denies a credential path in enforce mode without calling next', async () => {
    const fake = start()
    const listener = fake.listener('tools/pre-execute')
    const envPath = path.join(dir, '.env')
    await writeFile(envPath, 'SECRET=1\n')
    const next = vi.fn(async () => ({ kind: 'allow' }))

    const decision = (await listener(makeExec('read', { file_path: envPath }), next)) as {
      kind: string
      reason?: string
    }

    expect(decision.kind).toBe('deny')
    expect(decision.reason).toBeTruthy()
    expect(decision.reason).not.toContain(envPath)
    expect(next).not.toHaveBeenCalled()
  })

  it('allows .env.example and normal calls', async () => {
    const fake = start()
    const listener = fake.listener('tools/pre-execute')
    const next = vi.fn(async () => ({ kind: 'allow' }))

    const example = (await listener(
      makeExec('read', { file_path: path.join(dir, '.env.example') }),
      next,
    )) as { kind: string }
    expect(example.kind).toBe('allow')
    expect(next).toHaveBeenCalledTimes(1)

    const normal = (await listener(
      makeExec('read', { file_path: path.join(dir, 'README.md') }),
      next,
    )) as {
      kind: string
    }
    expect(normal.kind).toBe('allow')
    expect(next).toHaveBeenCalledTimes(2)
  })

  it('monitor mode audits a deny and still calls next', async () => {
    const fake = start({ mode: 'monitor' })
    const listener = fake.listener('tools/pre-execute')
    const envPath = path.join(dir, '.env')
    const next = vi.fn(async () => ({ kind: 'allow' }))

    const decision = (await listener(makeExec('read', { file_path: envPath }), next)) as {
      kind: string
    }
    expect(decision.kind).toBe('allow')
    expect(next).toHaveBeenCalledTimes(1)

    const records = await readAudit()
    expect(records.some((record) => record.action === 'monitored')).toBe(true)
    expect(JSON.stringify(records)).not.toContain(envPath)
  })

  it('short-circuits post-execute on a hit, redacts value, and never delegates', async () => {
    const fake = start()
    const listener = fake.listener('tools/post-execute')
    const next = vi.fn(async () => ({ kind: 'accept' }))
    const exec = makeExec('read', { file_path: path.join(dir, 'config.yaml') })
    const value = {
      path: 'config.yaml',
      offset: 0,
      lines: [{ number: 7, text: `aws_key: ${AWS_KEY}` }],
      totalLines: 1,
    }
    const result = makeResult(`aws_key: ${AWS_KEY}`, value)

    const decision = (await listener(exec, result, next)) as {
      kind: string
      value?: { offset: number; lines: Array<{ number: number; text: string }> }
    }

    expect(decision.kind).toBe('accept')
    expect(next).not.toHaveBeenCalled()
    expect(decision.value?.offset).toBe(0)
    expect(decision.value?.lines[0]?.number).toBe(7)
    expect(decision.value?.lines[0]?.text).toContain('[SECRET:aws-access-key:')
    expect(JSON.stringify(decision)).not.toContain(AWS_KEY)

    const records = await readAudit()
    expect(records.some((record) => record.spillBypassed === true)).toBe(true)
  })

  it('delegates post-execute when no rule matches', async () => {
    const fake = start()
    const listener = fake.listener('tools/post-execute')
    const next = vi.fn(async () => ({ kind: 'accept' }))
    const exec = makeExec('read', { file_path: path.join(dir, 'README.md') })
    const result = makeResult('ordinary text', {
      path: 'README.md',
      offset: 0,
      lines: [],
      totalLines: 0,
    })

    const decision = (await listener(exec, result, next)) as { kind: string }
    expect(decision.kind).toBe('accept')
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('redacts the durable PTC log copy without delegating', async () => {
    const fake = start()
    const listener = fake.listener('tools/ptc-dispatch-log')
    const next = vi.fn(async () => [])
    const dispatch = {
      exec: makeExec('run_code', { code: 'x' }),
      agent: makeAgent(dir),
      subCallId: 'call-1:ptc:1',
      name: 'read',
      isError: false,
      content: [{ type: 'text', text: `token ${AWS_KEY}` }],
    }

    const blocks = (await listener(dispatch, next)) as Array<{ type: string; text?: string }>
    expect(next).not.toHaveBeenCalled()
    expect(blocks[0]?.text).toContain('[SECRET:aws-access-key:')
    expect(blocks[0]?.text).not.toContain(AWS_KEY)
  })

  it('redacts system prompt sections, contexts, and variables but keeps tools', async () => {
    const fake = start({ levels: { input: 'aggressive', output: 'aggressive' } })
    const listener = fake.listener('system-prompt/assemble')
    const tools = [{ name: 'read' }]
    const assembly = {
      sections: [{ name: 'repo', text: `key ${AWS_KEY}` }],
      contexts: [{ name: 'ctx', text: `mail ${EMAIL}` }],
      tools,
      variables: { raw: AWS_KEY, empty: undefined },
    }
    const next = vi.fn(async () => assembly)

    const result = (await listener(assembly, {}, next)) as {
      sections: Array<{ text: string }>
      contexts: Array<{ text: string }>
      tools: unknown
      variables: Record<string, string | undefined>
    }

    expect(result.sections[0]?.text).toContain('[SECRET:aws-access-key:')
    expect(result.contexts[0]?.text).toContain('[[PII_EMAIL_')
    expect(result.variables.raw).toContain('[SECRET:aws-access-key:')
    expect(result.variables.empty).toBeUndefined()
    expect(result.tools).toBe(tools)
  })

  it('keeps plaintext out of every audit record', async () => {
    const fake = start()
    const pre = fake.listener('tools/pre-execute')
    const next = vi.fn(async () => ({ kind: 'allow' }))
    const envPath = path.join(dir, '.env')
    await listener(pre, next, makeExec('read', { file_path: envPath }))

    const records = await readAudit()
    const serialized = JSON.stringify(records)
    expect(serialized).not.toContain(envPath)
    expect(serialized).not.toContain(AWS_KEY)
    expect(serialized).not.toContain(ANTHROPIC_KEY)
    expect(serialized).not.toContain(EMAIL)
  })
})

async function listener(
  listenerFn: (...args: unknown[]) => unknown,
  next: (...args: unknown[]) => unknown,
  ...args: unknown[]
): Promise<unknown> {
  return listenerFn(...args, next)
}
