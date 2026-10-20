/**
 * Every string a user or the model can see from the guard is built here, so
 * approval prompts, denial reasons, notices, and `/guard` output share one
 * voice. Approval prompts are always returned in both languages for the DSH
 * UI; every other surface receives the active `GuardLocale`.
 * @module dsh-sensitive-guard/messages
 */
import type { RedactionHit } from './contracts.js'
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
    locale === 'zh'
      ? '  提示: /guard on|off 只影响当前进程'
      : '  note: /guard on|off changes this process only',
  ].join(NL)
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
    ['restore <placeholder> <file>', 'write one restored PII value (mode 0600)'],
  ],
  zh: [
    ['status', '显示当前设置'],
    ['on', '当前进程启用 enforce'],
    ['off', '当前进程切换为 monitor'],
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
