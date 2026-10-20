/**
 * End-to-end profile test: install this checkout into a disposable headless
 * DSH profile, route the model to a local OpenAI-compatible mock, and assert
 * that secrets/PII never reach the provider request or the audit log.
 */
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const repo = process.cwd()
const dsh = path.join(repo, 'node_modules', '.bin', 'dsh')
const secret = 'AKIA' + '1234567890' + 'ABCDEF'
const email = 'alice@example.com'
const bodies = []

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

function run(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(dsh, args, {
      cwd: repo,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      reject(new Error('dsh timed out: ' + args.join(' ')))
    }, 120_000)
    child.stdout.on('data', (chunk) => (stdout += chunk))
    child.stderr.on('data', (chunk) => (stderr += chunk))
    child.on('close', (code) => {
      clearTimeout(timer)
      resolve({ code, stdout, stderr })
    })
    child.on('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
  })
}

const server = createServer((request, response) => {
  const chunks = []
  request.on('data', (chunk) => chunks.push(chunk))
  request.on('end', () => {
    bodies.push(Buffer.concat(chunks).toString('utf8'))
    response.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
    })
    const base = {
      id: 'chatcmpl-mock',
      object: 'chat.completion.chunk',
      created: Math.floor(Date.now() / 1000),
      model: 'mock-model',
    }
    response.write(
      'data: ' +
        JSON.stringify({
          ...base,
          choices: [{ index: 0, delta: { role: 'assistant', content: 'OK' }, finish_reason: null }],
        }) +
        '\n\n',
    )
    response.write(
      'data: ' +
        JSON.stringify({
          ...base,
          choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
        }) +
        '\n\n',
    )
    response.write('data: [DONE]\n\n')
    response.end()
  })
})

let home
let work

try {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  home = await mkdtemp(path.join(os.tmpdir(), 'sg-e2e-home-'))
  work = await mkdtemp(path.join(os.tmpdir(), 'sg-e2e-work-'))
  const audit = path.join(home, 'audit.jsonl')
  const key = path.join(home, 'pii.key')
  const patch = path.join(home, 'e2e.patch.yml')
  const env = { DSH_HOME: home, MOCK_API_KEY: 'test-key' }

  await writeFile(
    patch,
    `- id: llm-pi-ai
  config:
    providers:
      mock:
        api: openai-completions
        baseURL: http://127.0.0.1:${port}/v1
        apiKeyEnv: MOCK_API_KEY
        models:
          - id: mock-model
            contextWindow: 8192
- id: agent-default-model
  config:
    provider: mock
    model: mock-model
- id: sensitive-guard
  config:
    mode: monitor
    redact:
      userMessages: true
      toolResults: true
      systemPrompt: true
      ptcLog: true
      notify: true
    audit:
      enabled: true
      path: ${audit}
    pii:
      keyFile: ${key}
`,
  )

  let result = await run(
    ['--profile', 'e2e', '--from-default-profile', 'headless', '--dump-config'],
    env,
  )
  assert(result.code === 0, 'profile initialization failed: ' + result.stderr.slice(-800))
  assert(result.stdout.includes('@deepseek-ai/dsh-headless'), 'headless template was not applied')

  result = await run(['plugin', '--profile', 'e2e', 'add', 'link:' + repo], env)
  assert(result.code === 0, 'plugin install failed: ' + result.stderr.slice(-800))

  result = await run(
    [
      '--profile',
      'e2e',
      '--patch',
      patch,
      `Remember key=${secret} mail=${email}. Reply with exactly OK and do not use tools.`,
    ],
    env,
  )
  assert(result.code === 0, 'headless run failed: ' + result.stderr.slice(-1200))
  assert(result.stdout.trim().includes('OK'), 'mock response was not returned')

  assert(bodies.length > 0, 'mock provider received no request')
  for (const body of bodies) {
    assert(!body.includes(secret), 'provider request leaked the AWS key')
    assert(!body.includes(email), 'provider request leaked the email')
    assert(body.includes('[SECRET:aws-access-key:'), 'provider request lacks a secret placeholder')
    assert(body.includes('[[PII_EMAIL_'), 'provider request lacks a PII placeholder')
  }
  assert(
    bodies.some((body) => body.includes('Sensitive Guard redacted')),
    'no provider request included the notify notice',
  )

  const auditText = await readFile(audit, 'utf8')
  assert(!auditText.includes(secret), 'audit log leaked the AWS key')
  assert(!auditText.includes(email), 'audit log leaked the email')
  assert(auditText.includes('"category":"aws-access-key"'), 'audit lacks the AWS category')
  assert(auditText.includes('"category":"email"'), 'audit lacks the email category')

  process.stdout.write(
    `e2e ok: ${bodies.length} provider request(s), ${auditText.trim().split('\n').length} audit record(s)\n`,
  )
} finally {
  await new Promise((resolve) => server.close(resolve))
  if (home !== undefined) await rm(home, { recursive: true, force: true })
  if (work !== undefined) await rm(work, { recursive: true, force: true })
}
