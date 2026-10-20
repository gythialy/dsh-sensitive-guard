/**
 * Every string a user or the model can see from the guard is built here, so
 * approval prompts, denial reasons, notices, and `/guard` output share one
 * voice. Approval prompts are always returned in both languages for the DSH
 * UI; every other surface receives the active `GuardLocale`.
 * @module dsh-sensitive-guard/messages
 */
import type { RedactionHit } from './contracts.js'
import type { CanaryCode, CanaryResult } from './egress/canary.js'
import type { EgressSnapshot } from './egress/index.js'
import type { EgressReport } from './egress/report.js'
import type { GuardLocale } from './locale.js'

export type { GuardLocale } from './locale.js'

const NL = String.fromCharCode(10)

/** Stable model-facing reason for a failed rule evaluation. */
export const EVALUATION_FAILURE_REASON = 'Policy evaluation failed while checking this call.'

/** The one-line approval instruction shown with every localized prompt. */
const APPROVAL_HINT_EN = 'Approve once only if you expect this exact call; otherwise cancel.'
const APPROVAL_HINT_ZH = '仅确认本次调用符合预期时允许；否则取消。'

/** Guidance already present in a rule reason does not need a second action. */
const GUIDANCE_EN = /\b(?:ask|choose|contact|provide|read|remove|run|send|use)\b/i
const GUIDANCE_ZH = /(?:请|使用|删除|读取|询问|运行|发送|确认|选择)/u

export interface LocalizedText {
  en: string
  zh: string
}

/** One redacted operation summary, localized for the approval UI. */
export interface LocalizedAction {
  en: string
  zh: string
}

/** Risk categories shown instead of raw rule text. */
export type RiskKind =
  | 'arguments-too-large'
  | 'secret-in-arguments'
  | 'embedded-credentials'
  | 'credential-query'
  | 'sensitive-path'
  | 'high-risk-command'
  | 'policy-approval'
  | 'default-approval'
  | 'evaluation-failed'

export interface Risk {
  kind: RiskKind
  /** Rule-supplied explanation; sanitized before display. */
  detail?: string
}

interface RiskCopy {
  label: LocalizedText
  why: LocalizedText
  denyAction: LocalizedText
}

const RISK_COPY: Record<RiskKind, RiskCopy> = {
  'arguments-too-large': {
    label: { en: 'arguments over the size limit', zh: '参数超过大小限制' },
    why: {
      en: 'The serialized arguments exceed the configured size limit.',
      zh: '序列化后的参数超过配置的大小限制。',
    },
    denyAction: { en: 'Send a smaller request.', zh: '请缩小请求' },
  },
  'secret-in-arguments': {
    label: { en: 'credential in arguments', zh: '参数中包含凭据' },
    why: {
      en: 'A credential pattern matched inside the tool arguments.',
      zh: '工具参数中匹配到凭据模式。',
    },
    denyAction: {
      en: 'Remove the credential or ask the user for a redacted value.',
      zh: '请移除凭据，或向用户索取脱敏后的值',
    },
  },
  'embedded-credentials': {
    label: { en: 'credentials embedded in a URL', zh: 'URL 内嵌凭据' },
    why: {
      en: 'The outbound URL includes a username or password.',
      zh: '出站 URL 包含用户名或密码。',
    },
    denyAction: {
      en: 'Remove the credentials and use a secret store.',
      zh: '请移除凭据并使用密钥存储',
    },
  },
  'credential-query': {
    label: { en: 'credential-like URL query', zh: 'URL 查询参数包含疑似凭据' },
    why: { en: 'A query parameter looks like a credential.', zh: '查询参数看起来像凭据。' },
    denyAction: { en: 'Ask the user to confirm this request.', zh: '请让用户确认此请求' },
  },
  'sensitive-path': {
    label: { en: 'sensitive path', zh: '敏感路径' },
    why: {
      en: "The path matches the guard's credential-path rules.",
      zh: '路径命中了守卫的凭据路径规则。',
    },
    denyAction: {
      en: 'Ask the user for an allowed path or a redacted copy.',
      zh: '请向用户索取允许的路径或脱敏副本',
    },
  },
  'high-risk-command': {
    label: { en: 'high-risk command', zh: '高风险命令' },
    why: {
      en: 'The command matches a built-in high-risk rule.',
      zh: '命令命中了内置高风险规则。',
    },
    denyAction: {
      en: 'Ask the user to run it manually if they intend it.',
      zh: '如确需执行，请让用户手动运行',
    },
  },
  'policy-approval': {
    label: { en: 'policy rule', zh: '策略规则' },
    why: {
      en: 'A project or baseline rule selected this call.',
      zh: '项目或内置规则选中了本次调用。',
    },
    denyAction: { en: 'Ask the user how to proceed.', zh: '请先询问用户如何处理' },
  },
  'default-approval': {
    label: { en: 'default policy', zh: '默认策略' },
    why: {
      en: 'No rule matched, so the configured default decision applies.',
      zh: '没有规则匹配，因此使用配置的默认决定。',
    },
    denyAction: { en: 'Ask the user how to proceed.', zh: '请先询问用户如何处理' },
  },
  'evaluation-failed': {
    label: { en: 'evaluation failure', zh: '策略评估失败' },
    why: {
      en: 'The guard could not evaluate its rule set.',
      zh: '守卫无法评估规则集。',
    },
    denyAction: {
      en: 'Ask the user to check the rule file.',
      zh: '请让用户检查规则文件',
    },
  },
}

export interface LocalizedReason {
  en: string
  zh: string
  readonly [locale: string]: string
}

/** Tool names are host-controlled; strip anything that could break a prompt. */
function displayToken(value: string): string {
  const token = value.replace(/[^\w.:/-]+/g, '').slice(0, 64)
  return token.length > 0 ? token : 'tool'
}

/** Normalize an action summary without changing its command or path text. */
export function cleanAction(action: string | undefined): string | undefined {
  if (action === undefined) return undefined
  const normalized = action
    .replace(/\p{Cc}+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (normalized.length === 0) return undefined
  return normalized.length > 160 ? normalized.slice(0, 157).trimEnd() + '…' : normalized
}

/**
 * Collapse a rule reason to one bounded sentence. Reasons are authored without
 * secrets, but a project file can still contain newlines or control bytes.
 */
export function cleanDetail(detail: string | undefined): string | undefined {
  if (detail === undefined) return undefined
  const normalized = detail
    .replace(/^sensitive-guard:\s*/i, '')
    .replace(/\p{Cc}+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (normalized.length === 0) return undefined
  const sentence = normalized.replace(/[.!?;:。！？；：]+$/u, '')
  return sentence.length > 220 ? sentence.slice(0, 217).trimEnd() + '…' : sentence
}

function hasCjk(value: string): boolean {
  return /[\u3400-\u9fff]/u.test(value)
}

/**
 * Prefer a rule's own explanation only when it matches the display language;
 * project and baseline reasons are usually English, so Chinese falls back to
 * the built-in category explanation instead of mixing languages.
 */
function explanation(risk: Risk, copy: RiskCopy, locale: GuardLocale): string {
  const detail = cleanDetail(risk.detail)
  if (detail !== undefined && (locale === 'en' || hasCjk(detail))) return detail
  const fallback = copy.why[locale]
  return cleanDetail(fallback) ?? fallback
}

function hasGuidance(why: string): boolean {
  return GUIDANCE_EN.test(why) || GUIDANCE_ZH.test(why)
}

/**
 * Localized approval prompt. The web UI collapses newlines, so this stays one
 * line; the action summary is already redacted by the caller.
 */
export function approvalPrompt(
  tool: string,
  risk: Risk,
  action?: LocalizedAction,
): LocalizedReason {
  const copy = RISK_COPY[risk.kind]
  const name = displayToken(tool)
  const enSummary = cleanAction(action?.en)
  const zhSummary = cleanAction(action?.zh)
  const enWhy = explanation(risk, copy, 'en')
  const zhWhy = explanation(risk, copy, 'zh')
  const enAction = enSummary === undefined ? '' : ' · Action: ' + enSummary
  const zhAction = zhSummary === undefined ? '' : ' · 操作：' + zhSummary
  return {
    en:
      'Sensitive Guard · Tool: ' +
      name +
      ' · Type: ' +
      copy.label.en +
      enAction +
      '. ' +
      enWhy +
      '. ' +
      APPROVAL_HINT_EN,
    zh:
      '敏感信息守卫 · 工具：' +
      name +
      ' · 类型：' +
      copy.label.zh +
      zhAction +
      '。' +
      zhWhy +
      '。' +
      APPROVAL_HINT_ZH,
  }
}

/** Model-facing approval reason; the localized prompt is rendered separately. */
export function approvalReason(tool: string, risk: Risk, locale: GuardLocale = 'en'): string {
  const copy = RISK_COPY[risk.kind]
  const name = displayToken(tool)
  const why = explanation(risk, copy, locale)
  return locale === 'zh'
    ? '敏感信息守卫需要确认 ' + name + ' 调用：' + copy.label.zh + '。' + why + '。'
    : 'Sensitive Guard needs approval for the ' +
        name +
        ' call: ' +
        copy.label.en +
        '. ' +
        why +
        '.'
}

/** Model-facing denial: name the risk, explain it, and give one safe next step. */
export function denyReason(tool: string, risk: Risk, locale: GuardLocale = 'en'): string {
  const copy = RISK_COPY[risk.kind]
  const name = displayToken(tool)
  const why = explanation(risk, copy, locale)
  const action = hasGuidance(why) ? '' : copy.denyAction[locale]
  return locale === 'zh'
    ? '敏感信息守卫已阻止 ' +
        name +
        ' 调用：' +
        copy.label.zh +
        '。' +
        why +
        '。' +
        (action ? action + '。' : '')
    : 'Sensitive Guard blocked the ' +
        name +
        ' call: ' +
        copy.label.en +
        '. ' +
        why +
        '.' +
        (action ? ' ' + action : '')
}

/** Count-only notice; category names and counts are never sensitive. */
export function noticeText(hits: readonly RedactionHit[], locale: GuardLocale = 'en'): string {
  const categories = hits
    .map((hit) => hit.category + '×' + hit.count)
    .join(locale === 'zh' ? '、' : ', ')
  return locale === 'zh'
    ? '敏感信息守卫已脱敏：' + categories + '。原值已替换为占位符。'
    : 'Sensitive Guard redacted: ' + categories + '. The originals were replaced with placeholders.'
}

/** Compact egress state reused by `/guard status` and the startup line. */
export interface EgressSummary {
  bound: boolean
  port: number
  mode: string
  envMatches: boolean
}

export interface GuardStatus {
  mode: string
  failClosed: boolean
  inputLevel: string
  outputLevel: string
  policyRules: number
  redactionRules: number
  auditEnabled: boolean
  auditPath: string
  piiEnabled: boolean
  piiRestore: boolean
  /** Absent when `egress.enabled` is off. */
  egress?: EgressSummary
}

/** `/guard status`: a short key-value block, not a machine status line. */
export function statusText(status: GuardStatus, locale: GuardLocale = 'en'): string {
  const on = locale === 'zh' ? '开' : 'on'
  const off = locale === 'zh' ? '关' : 'off'
  const audit = status.auditEnabled ? on + ' — ' + status.auditPath : off
  return [
    locale === 'zh' ? '敏感信息守卫' : 'Sensitive Guard',
    (locale === 'zh' ? '  模式: ' : '  mode: ') + status.mode,
    (locale === 'zh' ? '  失败关闭: ' : '  fail closed: ') + (status.failClosed ? on : off),
    (locale === 'zh' ? '  等级: 输入=' : '  levels: input=') +
      status.inputLevel +
      (locale === 'zh' ? '，输出=' : ', output=') +
      status.outputLevel,
    (locale === 'zh' ? '  规则: 策略=' : '  rules: policy=') +
      status.policyRules +
      (locale === 'zh' ? '，脱敏=' : ', redaction=') +
      status.redactionRules,
    (locale === 'zh' ? '  审计: ' : '  audit: ') + audit,
    (locale === 'zh' ? '  PII: ' : '  pii: ') + (status.piiEnabled ? on : off),
    (locale === 'zh' ? '  PII 恢复: ' : '  pii restore: ') + (status.piiRestore ? on : off),
    ...(status.egress === undefined ? [] : [egressSummaryLine(status.egress, locale)]),
    locale === 'zh'
      ? '  提示: /guard on|off 只影响当前进程'
      : '  note: /guard on|off changes this process only',
  ].join(NL)
}

/** One-line egress state for `/guard status` and the startup line. */
export function egressSummaryLine(summary: EgressSummary, locale: GuardLocale = 'en'): string {
  const zh = locale === 'zh'
  const state = summary.bound ? (zh ? '已绑定' : 'bound') : zh ? '未绑定' : 'not bound'
  const wiring = summary.envMatches
    ? zh
      ? '环境正常'
      : 'env ok'
    : zh
      ? '环境未接线'
      : 'env not wired'
  return (
    (zh ? '  出站守卫: ' : '  egress: ') +
    '127.0.0.1:' +
    String(summary.port) +
    ' ' +
    state +
    ' (' +
    summary.mode +
    '), ' +
    wiring
  )
}

/** `/guard egress status`: listener, wiring, rules, counters, and recents. */
export function egressStatusText(snapshot: EgressSnapshot, locale: GuardLocale = 'en'): string {
  const zh = locale === 'zh'
  const lines = [zh ? '敏感信息守卫出站守卫' : 'Sensitive Guard egress']
  lines.push(
    (zh ? '  监听: ' : '  listener: ') +
      snapshot.host +
      ':' +
      String(snapshot.port) +
      ' — ' +
      (snapshot.bound ? (zh ? '已绑定' : 'bound') : zh ? '未绑定' : 'not bound') +
      ' (' +
      snapshot.mode +
      ')',
  )
  lines.push(
    (zh ? '  接线: ' : '  wiring: ') +
      (snapshot.envMatches
        ? zh
          ? 'https_proxy 指向本监听（正常）'
          : 'https_proxy points at this listener (ok)'
        : snapshot.proxyEnv === undefined
          ? zh
            ? 'https_proxy 未设置，流量不被覆盖'
            : 'https_proxy is not set; traffic is not covered'
          : zh
            ? 'https_proxy 指向别处: ' + snapshot.proxyEnv
            : 'https_proxy points elsewhere: ' + snapshot.proxyEnv),
  )
  lines.push(
    (zh ? '  规则: ' : '  rules: ') +
      'deny=' +
      String(snapshot.denyRules) +
      (zh ? '，allow=' : ', allow=') +
      String(snapshot.allowRules) +
      (zh ? '，未知=' : ', unknown=') +
      snapshot.unknown,
  )
  if (snapshot.upstream !== undefined) {
    lines.push((zh ? '  上游: ' : '  upstream: ') + snapshot.upstream)
  }
  lines.push(
    (zh ? '  流量: ' : '  traffic: ') +
      (zh ? '隧道=' : 'tunnels=') +
      String(snapshot.counts.tunnels) +
      (zh ? '，拦截=' : ', blocked=') +
      String(snapshot.counts.denied) +
      (zh ? '，入=' : ', in=') +
      formatBytes(snapshot.counts.bytesIn) +
      (zh ? '，出=' : ', out=') +
      formatBytes(snapshot.counts.bytesOut),
  )
  if (snapshot.recent.length > 0) {
    lines.push(
      (zh ? '  最近: ' : '  recent: ') +
        snapshot.recent
          .map(
            (entry) =>
              entry.host +
              ':' +
              String(entry.port) +
              ' ' +
              entry.decision +
              (entry.enforced ? '!' : '') +
              '(' +
              entry.reason +
              ')',
          )
          .join(zh ? '、' : ', '),
    )
  }
  if (snapshot.lastCanary !== undefined) {
    lines.push((zh ? '  探针: ' : '  canary: ') + snapshot.lastCanary.code)
  }
  if (!snapshot.envMatches) {
    lines.push(
      zh
        ? '  提示: 启动前在 $DSH_HOME/.env 设置 https_proxy=http://127.0.0.1:' +
            String(snapshot.port)
        : '  hint: set https_proxy=http://127.0.0.1:' +
            String(snapshot.port) +
            ' in $DSH_HOME/.env before launch',
    )
  }
  return lines.join(NL)
}

function canaryDetail(code: CanaryCode, zh: boolean): string {
  switch (code) {
    case 'ok':
      return zh ? '成功' : 'ok'
    case 'refused':
      return zh ? '连接被拒绝，监听未运行' : 'connection refused; the listener is not running'
    case 'timeout':
      return zh ? '超时' : 'timed out'
    case 'denied':
      return zh
        ? '被守卫策略拒绝（127.0.0.1 在 deny 列表里？）'
        : 'refused by guard policy (is 127.0.0.1 denied?)'
    case 'protocol':
      return zh ? 'CONNECT 响应无法识别' : 'unrecognised CONNECT response'
    case 'echo-mismatch':
      return zh ? '隧道回显不一致' : 'tunnel echo did not match'
  }
}

/** Result of one canary probe, including what to check when it fails. */
export function egressCanaryText(
  result: CanaryResult,
  port: number,
  locale: GuardLocale = 'en',
): string {
  const zh = locale === 'zh'
  const detail = canaryDetail(result.code, zh)
  const latency = String(result.latencyMs) + (zh ? ' 毫秒' : ' ms')
  if (result.ok) {
    return zh
      ? '敏感信息守卫探针: ' + detail + '（' + latency + '）。'
      : 'Sensitive Guard canary: ' + detail + ' (' + latency + ').'
  }
  return (
    (zh ? '敏感信息守卫探针失败: ' : 'Sensitive Guard canary failed: ') +
    detail +
    '（' +
    latency +
    '）。' +
    NL +
    (zh
      ? '请确认启动环境里设置了 https_proxy=http://127.0.0.1:' +
        String(port) +
        '，且该端口是本进程监听的端口。'
      : 'Check that the launch environment sets https_proxy=http://127.0.0.1:' +
        String(port) +
        ' and that this process owns that port.')
  )
}

/** `/guard egress report`: destinations aggregated from the audit log. */
export function egressReportText(report: EgressReport, locale: GuardLocale = 'en'): string {
  const zh = locale === 'zh'
  const since = new Date(report.sinceTs).toISOString()
  const heading = zh
    ? '敏感信息守卫出站报告（自 ' + since + ' 起）'
    : 'Sensitive Guard egress report (since ' + since + ')'

  if (report.connects === 0) {
    return [
      heading,
      zh
        ? '  窗口内没有连接记录。先跑一些流量，或放宽 --since。'
        : '  no connect records in this window; run some traffic or widen --since.',
      egressReportUsage(locale),
    ].join(NL)
  }

  const lines = [heading]
  lines.push(
    (zh ? '  记录: ' : '  records: ') +
      String(report.connects) +
      (zh ? ' 次连接，' : ' connects, ') +
      String(report.denied) +
      (zh ? ' 次拦截，' : ' blocked, ') +
      String(report.entries.length) +
      (zh ? ' 个目标，' : ' destinations, ') +
      String(report.files) +
      (zh ? ' 个文件' : ' file(s)'),
  )
  lines.push(zh ? '  高频目标:' : '  top destinations:')
  for (const entry of report.entries.slice(0, 10)) {
    const target = entry.host + ':' + String(entry.port)
    const label = entry.denied === 0 ? 'allow' : entry.allowed === 0 ? 'blocked' : 'allow+blocked'
    lines.push('    ' + target.padEnd(34) + String(entry.connects).padStart(6) + '  ' + label)
  }
  if (report.entries.length > 10) {
    const more = report.entries.length - 10
    lines.push(
      zh
        ? '    …还有 ' + String(more) + ' 个目标'
        : '    … ' + String(more) + ' more destination(s)',
    )
  }
  if (report.truncated) {
    lines.push(
      zh
        ? '  注意: 超出报告大小上限，较早的轮转日志未读取。'
        : '  note: the byte budget cut older rotations from this report.',
    )
  }
  lines.push(
    zh
      ? '  提示: /guard egress report --yaml 输出可粘贴的 allow 清单。'
      : '  hint: /guard egress report --yaml prints a suggested allowlist.',
  )
  return lines.join(NL)
}

export function egressReportUsage(locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '用法: /guard egress report [--since 7d] [--yaml]'
    : 'Usage: /guard egress report [--since 7d] [--yaml]'
}

export function egressReportInvalidSince(locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '敏感信息守卫: --since 接受 30s、15m、24h、7d 或 ISO 日期。' + NL + egressReportUsage('zh')
    : 'Sensitive Guard: --since accepts 30s, 15m, 24h, 7d, or an ISO date.' +
        NL +
        egressReportUsage('en')
}

export function egressReportFailed(locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '敏感信息守卫: 读取审计日志失败，报告未生成。'
    : 'Sensitive Guard: the audit log could not be read, so no report was produced.'
}

/** `/guard egress` before `egress.enabled`. */
export function egressDisabledText(locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '敏感信息守卫: 出站守卫未启用。设置 egress.enabled: true，并在启动环境里设置 https_proxy=http://127.0.0.1:<egress.port>，然后重启 DSH。'
    : 'Sensitive Guard: the egress guard is off. Set egress.enabled: true, export https_proxy=http://127.0.0.1:<egress.port> before launch, and restart DSH.'
}

/** `/guard egress` when the config is on but this process mounted nothing. */
export function egressUnavailableText(locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '敏感信息守卫: egress.enabled 已打开，但当前进程没有挂载监听。检查启动日志里的绑定错误。'
    : 'Sensitive Guard: egress.enabled is on but this process mounted no listener. Check the startup log for a bind error.'
}

/** Startup line emitted after the egress listener settles. */
export function egressStartupText(snapshot: EgressSnapshot, locale: GuardLocale = 'en'): string {
  const zh = locale === 'zh'
  const address = snapshot.host + ':' + String(snapshot.port)
  if (!snapshot.bound) {
    return zh
      ? '敏感信息守卫出站守卫未绑定（' + address + '）。'
      : 'Sensitive Guard egress guard is not bound (' + address + ').'
  }
  return snapshot.envMatches
    ? zh
      ? '敏感信息守卫出站守卫已就绪: ' + address + '，https_proxy 已接线。'
      : 'Sensitive Guard egress guard ready on ' + address + '; https_proxy is wired.'
    : zh
      ? '敏感信息守卫出站守卫已绑定 ' + address + '，但 https_proxy 未指向它：客户端流量不被覆盖。'
      : 'Sensitive Guard egress guard bound on ' +
        address +
        ' but https_proxy does not point at it: launched clients are not covered.'
}

/** `/guard on|off` confirmation; the mode is never persisted. */
export function modeText(mode: string, locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '敏感信息守卫模式：' + mode + '（仅当前进程；重启后恢复配置模式）。'
    : 'Sensitive Guard mode: ' + mode + ' (runtime only; a restart restores the configured mode).'
}

/** Startup line emitted once by the plugin. */
export function startupText(
  args: {
    mode: string
    policyRules: number
    redactionRules: number
    auditEnabled: boolean
  },
  locale: GuardLocale = 'en',
): string {
  if (locale === 'zh') {
    return (
      '敏感信息守卫已启用：' +
      args.mode +
      ' 模式 — ' +
      args.policyRules +
      ' 条策略规则，' +
      args.redactionRules +
      ' 条脱敏规则，审计' +
      (args.auditEnabled ? '已开启' : '已关闭') +
      '。'
    )
  }
  return (
    'Sensitive Guard active in ' +
    args.mode +
    ' mode — ' +
    args.policyRules +
    ' policy rules, ' +
    args.redactionRules +
    ' redaction rules, audit ' +
    (args.auditEnabled ? 'on' : 'off') +
    '.'
  )
}

const COMMANDS: Record<GuardLocale, Array<[string, string]>> = {
  en: [
    ['status', 'show the current settings'],
    ['on', 'enforce for this process'],
    ['off', 'monitor for this process'],
    ['egress [status|canary|report]', 'egress guard state, canary probe, destination report'],
    ['restore <placeholder> <file>', 'write one restored PII value (mode 0600)'],
  ],
  zh: [
    ['status', '显示当前设置'],
    ['on', '当前进程启用 enforce'],
    ['off', '当前进程切换为 monitor'],
    ['egress [status|canary|report]', '出站守卫状态、回环探针与目标统计'],
    ['restore <placeholder> <file>', '写入一个恢复的 PII 值（0600 权限）'],
  ],
}

export function guardUsage(locale: GuardLocale = 'en'): string {
  return [
    locale === 'zh' ? '用法: /guard <command>' : 'Usage: /guard <command>',
    ...COMMANDS[locale].map(([command, description]) => '  ' + command.padEnd(32) + description),
  ].join(NL)
}

export function restoreUsage(locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '用法: /guard restore <placeholder> <file>'
    : 'Usage: /guard restore <placeholder> <file>'
}

function displayVerb(value: string): string {
  const token = value
    .replace(/\p{Cc}+/gu, ' ')
    .replace(/["\\]/g, '')
    .trim()
    .slice(0, 32)
  return token.length > 0 ? token : 'unknown'
}

export function unknownCommandText(verb: string, locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '敏感信息守卫：未知命令 "' + displayVerb(verb) + '"。' + NL + guardUsage('zh')
    : 'Sensitive Guard: unknown command "' + displayVerb(verb) + '".' + NL + guardUsage('en')
}

export function restoreDisabledText(locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '敏感信息守卫：PII 恢复未开启。请在插件配置中设置 pii.restore: true，并在生成占位符的脱敏发生前重启。'
    : 'Sensitive Guard: PII restore is off. Set pii.restore: true in the plugin config and restart before the redaction that mints the placeholder.'
}

export function restoreMissingText(locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '敏感信息守卫：restore 需要占位符和目标文件。' + NL + restoreUsage('zh')
    : 'Sensitive Guard: restore needs both a placeholder and a target file.' +
        NL +
        restoreUsage('en')
}

export function restoreInvalidText(locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '敏感信息守卫：restore 只接受 [[PII_<TYPE>_<hash8>]] 占位符。'
    : 'Sensitive Guard: restore accepts only [[PII_<TYPE>_<hash8>]] placeholders.'
}

export function restoreUnknownText(locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '敏感信息守卫：当前进程中不存在该占位符。请先在生成它的脱敏之前启用 pii.restore。'
    : 'Sensitive Guard: this placeholder is not available in the current process. Enable pii.restore before the redaction that minted it.'
}

export function restoreExistsText(file: string, locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '敏感信息守卫：' + file + ' 已存在；请换一个新路径。'
    : 'Sensitive Guard: ' + file + ' already exists; choose a new path.'
}

export function restoreWriteFailedText(file: string, locale: GuardLocale = 'en'): string {
  return locale === 'zh'
    ? '敏感信息守卫：无法写入 ' + file + '。请检查路径和权限。'
    : 'Sensitive Guard: could not write ' + file + '. Check the path and permissions.'
}

export function restoreSuccessText(
  placeholder: string,
  file: string,
  locale: GuardLocale = 'en',
): string {
  return locale === 'zh'
    ? '敏感信息守卫：已将 ' + placeholder + ' 恢复到 ' + file + '（0600 权限，不覆盖）。'
    : 'Sensitive Guard: restored ' + placeholder + ' to ' + file + ' (mode 0600, no overwrite).'
}

/** Human-readable byte limit for "arguments too large" explanations. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return 'configured'
  if (bytes >= 1024 * 1024) return trimNumber(bytes / (1024 * 1024)) + ' MB'
  if (bytes >= 1024) return trimNumber(bytes / 1024) + ' KB'
  return bytes + ' B'
}

function trimNumber(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(1)
}
