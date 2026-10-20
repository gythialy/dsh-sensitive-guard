/**
 * End-to-end egress guard test. It launches the real headless profile with the
 * proxy environment pointing at the guard, has the mock provider call the
 * `bash` tool, and verifies that the host-spawned child's request traversed the
 * guard and was audited — including a denied variant that must never reach the
 * origin.
 *
 * The bash child is the same host-spawned process class as an MCP stdio child:
 * both inherit the launcher's `proxyEnvironmentForChild()` values through
 * `scrubbedParentEnv()`, so one run covers the seam for both.
 */
import { spawn, spawnSync } from 'node:child_process'
import { createServer } from 'node:http'
import { createServer as createTcpServer } from 'node:net'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const repo = process.cwd()
const dsh = path.join(repo, 'node_modules', '.bin', 'dsh')

if (spawnSync('curl', ['--version'], { stdio: 'ignore' }).status !== 0) {
  process.stdout.write('e2e egress skipped: curl is not available\n')
  process.exit(0)
}

let command = 'true'

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

/** The mock provider drives one bash call, then reports the final text. */
const provider = createServer((request, response) => {
  const chunks = []
  request.on('data', (chunk) => chunks.push(chunk))
  request.on('end', () => {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    const tools = Array.isArray(parsed.tools) ? parsed.tools : []
    const sawToolResult = parsed.messages.some((message) => message.role === 'tool')
    const base = {
      id: 'chatcmpl-mock',
      object: 'chat.completion.chunk',
      created: Math.floor(Date.now() / 1000),
      model: 'mock-model',
    }
    const send = (payload) => {
      response.write('data: ' + JSON.stringify(payload) + '\n\n')
    }
    response.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
    })
    if (tools.length === 0) {
      // Session-title request: plain text, no tool call.
      send({
        ...base,
        choices: [
          { index: 0, delta: { role: 'assistant', content: 'EGRESS' }, finish_reason: null },
        ],
      })
    } else if (!sawToolResult) {
      send({
        ...base,
        choices: [
          {
            index: 0,
            delta: {
              role: 'assistant',
              content: null,
              tool_calls: [
                {
                  index: 0,
                  id: 'call_1',
                  type: 'function',
                  function: {
                    name: 'bash',
                    arguments: JSON.stringify({ command, description: 'Run the egress probe' }),
                  },
                },
              ],
            },
            finish_reason: 'tool_calls',
          },
        ],
      })
    } else {
      send({
        ...base,
        choices: [{ index: 0, delta: { role: 'assistant', content: 'OK' }, finish_reason: null }],
      })
    }
    send({ ...base, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] })
    response.write('data: [DONE]\n\n')
    response.end()
  })
})

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createTcpServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port
      server.close(() => resolve(port))
    })
  })
}

async function waitForAudit(file, predicate, timeoutMs = 4000) {
  const started = Date.now()
  let text = ''
  while (Date.now() - started < timeoutMs) {
    text = await readFile(file, 'utf8').catch(() => '')
    if (predicate(text)) return text
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  return text
}

/**
 * One scenario: a fresh DSH_HOME, the plugin linked in, the guard configured,
 * and one bash call through the guard to a local origin.
 */
async function scenario({ name, enforce, deny }) {
  const home = await mkdtemp(path.join(os.tmpdir(), 'sg-e2e-egress-home-'))
  const audit = path.join(home, 'audit.jsonl')
  const patch = path.join(home, 'patch.yml')
  const guardPort = await freePort()
  const originPort = origin.address().port
  const before = originRequests.length

  const egress = [
    '    egress:',
    '      enabled: true',
    '      port: ' + guardPort,
    '      canary: false',
  ]
  if (deny) egress.push("      deny: ['127.0.0.1']")
  if (enforce) egress.push('')

  await writeFile(
    patch,
    [
      '- id: llm-pi-ai',
      '  config:',
      '    providers:',
      '      mock:',
      '        api: openai-completions',
      '        baseURL: http://127.0.0.1:' + providerPort + '/v1',
      '        apiKeyEnv: MOCK_API_KEY',
      '        models:',
      '          - id: mock-model',
      '            contextWindow: 8192',
      '- id: agent-default-model',
      '  config:',
      '    provider: mock',
      '    model: mock-model',
      '- id: sensitive-guard',
      '  config:',
      '    mode: ' + (enforce ? 'enforce' : 'monitor'),
      // Headless has no approval answerer; let unrelated tool calls through so
      // the test exercises the egress decision, not the approval policy.
      '    defaultDecision: allow',
      '    audit:',
      '      enabled: true',
      '      path: ' + audit,
      '    pii:',
      '      enabled: false',
      ...egress,
    ].join('\n'),
  )

  const env = {
    DSH_HOME: home,
    MOCK_API_KEY: 'test-key',
    // The launcher snapshots these before any plugin loads and republishes them
    // to every spawned child, which is the seam under test.
    HTTP_PROXY: 'http://127.0.0.1:' + guardPort,
    HTTPS_PROXY: 'http://127.0.0.1:' + guardPort,
    NO_PROXY: '',
  }

  command =
    "curl --noproxy '' -sS -x http://127.0.0.1:" +
    guardPort +
    ' http://127.0.0.1:' +
    originPort +
    '/e2e'

  try {
    let result = await run(
      ['--profile', name, '--from-default-profile', 'headless', '--dump-config'],
      env,
    )
    assert(
      result.code === 0,
      name + ': profile initialization failed: ' + result.stderr.slice(-600),
    )

    result = await run(['plugin', '--profile', name, 'add', 'link:' + repo], env)
    assert(result.code === 0, name + ': plugin install failed: ' + result.stderr.slice(-600))

    result = await run(['--profile', name, '--patch', patch, 'Run the probe command.'], env)
    assert(result.code === 0, name + ': headless run failed: ' + result.stderr.slice(-1200))
    assert(result.stdout.includes('OK'), name + ': mock response was not returned')

    const auditText = await waitForAudit(audit, (text) => text.includes('"phase":"egress"'))
    assert(
      auditText.includes('"phase":"egress"'),
      name + ': the guard wrote no egress audit records',
    )
    assert(
      auditText.includes('"host":"127.0.0.1"') && auditText.includes('"port":' + originPort),
      name + ': the audit lacks the origin destination',
    )

    if (deny) {
      assert(auditText.includes('"enforced":true'), name + ': the deny was not enforced')
      assert(originRequests.length === before, name + ': a denied request reached the origin')
    } else {
      assert(
        originRequests.length === before + 1,
        name + ': the proxied request did not reach the origin',
      )
      assert(
        originRequests[originRequests.length - 1] === '/e2e',
        name + ': the origin saw an unexpected path',
      )
    }
  } finally {
    await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 })
  }
}

// The origin is only reachable when the guard forwards the request.
const originRequests = []
const origin = createServer((request, response) => {
  originRequests.push(request.url ?? '')
  response.writeHead(200, { 'content-type': 'text/plain', 'content-length': '9' })
  response.end('egress-ok')
})

await listen(origin)
const providerPort = await new Promise((resolve) => {
  provider.listen(0, '127.0.0.1', () => resolve(provider.address().port))
})

const only = process.env.E2E_EGRESS_ONLY ?? ''
try {
  if (only === '' || only === 'allow') {
    await scenario({ name: 'egress-allow', enforce: false, deny: false })
  }
  if (only === '' || only === 'deny') {
    await scenario({ name: 'egress-deny', enforce: true, deny: true })
  }
  process.stdout.write(
    'e2e egress ok: ' + originRequests.length + ' proxied request(s), deny enforced\n',
  )
} finally {
  await new Promise((resolve) => provider.close(resolve))
  await new Promise((resolve) => origin.close(resolve))
}
