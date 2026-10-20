/**
 * Every string a user or the model can see from the guard is built here, so
 * approval prompts, denial reasons, notices, and `/guard` output share one
 * voice. Builders never accept argument values and never interpolate matched
 * paths, secrets, or full commands.
 * @module dsh-sensitive-guard/messages
 */
import type { RedactionHit } from './contracts.js'

const NL = String.fromCharCode(10)

/** Stable model-facing reason for a failed rule evaluation. */
export const EVALUATION_FAILURE_REASON = 'Policy evaluation failed while checking this call.'

/** The one-line approval instruction shown with every localized prompt. */
const APPROVAL_HINT = 'Approve once only if you expect this exact call; otherwise cancel.'
const APPROVAL_HINT_ZH = '仅确认本次调用符合预期时允许；否则取消。'

/** A denial whose reason already tells the model what to do needs no suffix. */
const GUIDANCE = /\b(?:ask|choose|contact|provide|read|remove|run|send|use)\b/i

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
  label: string
  zhLabel: string
  why: string
  denyAction: string
}

const RISK_COPY: Record<RiskKind, RiskCopy> = {
  'arguments-too-large': {
    label: 'arguments over the size limit',
    zhLabel: '参数超过大小限制',
    why: 'The serialized arguments exceed the configured size limit.',
    denyAction: 'Send a smaller request.',
  },
  'secret-in-arguments': {
    label: 'credential in arguments',
    zhLabel: '参数中包含凭据',
    why: 'A credential pattern matched inside the tool arguments.',
    denyAction: 'Remove the credential or ask the user for a redacted value.',
  },
  'embedded-credentials': {
    label: 'credentials embedded in a URL',
    zhLabel: 'URL 内嵌凭据',
    why: 'The outbound URL includes a username or password.',
    denyAction: 'Remove the credentials and use a secret store.',
  },
  'credential-query': {
    label: 'credential-like URL query',
    zhLabel: 'URL 查询参数包含疑似凭据',
    why: 'A query parameter looks like a credential.',
    denyAction: 'Ask the user to confirm this request.',
  },
  'sensitive-path': {
    label: 'sensitive path',
    zhLabel: '敏感路径',
    why: "The path matches the guard's credential-path rules.",
    denyAction: 'Ask the user for an allowed path or a redacted copy.',
  },
  'high-risk-command': {
    label: 'high-risk command',
    zhLabel: '高风险命令',
    why: 'The command matches a built-in high-risk rule.',
    denyAction: 'Ask the user to run it manually if they intend it.',
  },
  'policy-approval': {
    label: 'policy rule',
    zhLabel: '策略规则',
    why: 'A project or baseline rule selected this call.',
    denyAction: 'Ask the user how to proceed.',
  },
  'default-approval': {
    label: 'default policy',
    zhLabel: '默认策略',
    why: 'No rule matched, so the configured default decision applies.',
    denyAction: 'Ask the user how to proceed.',
  },
  'evaluation-failed': {
    label: 'evaluation failure',
    zhLabel: '策略评估失败',
    why: 'The guard could not evaluate its rule set.',
    denyAction: 'Ask the user to check the rule file.',
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

/** Prefer the rule's own explanation, then the built-in one, minus any period. */
function explanation(risk: Risk, copy: RiskCopy): string {
  return cleanDetail(risk.detail) ?? cleanDetail(copy.why) ?? copy.why
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
  const sentence = normalized.replace(/[.!?;:]+$/, '')
  return sentence.length > 220 ? sentence.slice(0, 217).trimEnd() + '…' : sentence
}

/** Localized approval prompt; the web UI collapses newlines, so keep one line. */
export function approvalPrompt(tool: string, risk: Risk): LocalizedReason {
  const copy = RISK_COPY[risk.kind]
  const why = explanation(risk, copy)
  const name = displayToken(tool)
  return {
    en: 'Sensitive Guard · ' + name + ' · Risk: ' + copy.label + '. ' + why + '. ' + APPROVAL_HINT,
    zh: '敏感信息守卫 · ' + name + ' · 风险：' + copy.zhLabel + '。' + APPROVAL_HINT_ZH,
  }
}

/** Model-facing approval reason; the localized prompt is rendered separately. */
export function approvalReason(tool: string, risk: Risk): string {
  const copy = RISK_COPY[risk.kind]
  const why = explanation(risk, copy)
  return (
    'Sensitive Guard needs approval for the ' +
    displayToken(tool) +
    ' call: ' +
    copy.label +
    '. ' +
    why +
    '.'
  )
}

/** Model-facing denial: name the risk, explain it, and give one safe next step. */
export function denyReason(tool: string, risk: Risk): string {
  const copy = RISK_COPY[risk.kind]
  const why = explanation(risk, copy)
  const action = GUIDANCE.test(why) ? '' : ' ' + copy.denyAction
  return (
    'Sensitive Guard blocked the ' +
    displayToken(tool) +
    ' call: ' +
    copy.label +
    '. ' +
    why +
    '.' +
    action
  )
}

/** Count-only notice; category names and counts are never sensitive. */
export function noticeText(hits: readonly RedactionHit[]): string {
  const categories = hits.map((hit) => hit.category + '×' + hit.count).join(', ')
  return (
    'Sensitive Guard redacted: ' + categories + '. The originals were replaced with placeholders.'
  )
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
export function statusText(status: GuardStatus): string {
  const audit = status.auditEnabled ? 'on — ' + status.auditPath : 'off'
  return [
    'Sensitive Guard',
    '  mode: ' + status.mode,
    '  fail closed: ' + (status.failClosed ? 'on' : 'off'),
    '  levels: input=' + status.inputLevel + ', output=' + status.outputLevel,
    '  rules: policy=' + status.policyRules + ', redaction=' + status.redactionRules,
    '  audit: ' + audit,
    '  pii: ' + (status.piiEnabled ? 'on' : 'off'),
    '  pii restore: ' + (status.piiRestore ? 'on' : 'off'),
    '  note: /guard on|off changes this process only',
  ].join(NL)
}

/** `/guard on|off` confirmation; the mode is never persisted. */
export function modeText(mode: string): string {
  return (
    'Sensitive Guard mode: ' + mode + ' (runtime only; a restart restores the configured mode).'
  )
}

/** Startup line emitted once by the plugin. */
export function startupText(args: {
  mode: string
  policyRules: number
  redactionRules: number
  auditEnabled: boolean
}): string {
  return (
    'Sensitive Guard active in ' +
    args.mode +
    ' mode — ' +
    args.policyRules +
    ' policy rules, ' +
    args.redactionRules +
    ' redaction rules, ' +
    'audit ' +
    (args.auditEnabled ? 'on' : 'off') +
    '.'
  )
}

const COMMANDS: Array<[string, string]> = [
  ['status', 'show the current settings'],
  ['on', 'enforce for this process'],
  ['off', 'monitor for this process'],
  ['restore <placeholder> <file>', 'write one restored PII value (mode 0600)'],
]

export const GUARD_USAGE = [
  'Usage: /guard <command>',
  ...COMMANDS.map(([command, description]) => '  ' + command.padEnd(32) + description),
].join(NL)

export const RESTORE_USAGE = 'Usage: /guard restore <placeholder> <file>'

function displayVerb(value: string): string {
  const token = value
    .replace(/\p{Cc}+/gu, ' ')
    .replace(/["\\]/g, '')
    .trim()
    .slice(0, 32)
  return token.length > 0 ? token : 'unknown'
}

export function unknownCommandText(verb: string): string {
  return 'Sensitive Guard: unknown command "' + displayVerb(verb) + '".' + NL + GUARD_USAGE
}

export const RESTORE_DISABLED_TEXT =
  'Sensitive Guard: PII restore is off. Set pii.restore: true in the plugin config and restart before the redaction that mints the placeholder.'

export const RESTORE_MISSING_TEXT =
  'Sensitive Guard: restore needs both a placeholder and a target file.' + NL + RESTORE_USAGE

export const RESTORE_INVALID_TEXT =
  'Sensitive Guard: restore accepts only [[PII_<TYPE>_<hash8>]] placeholders.'

export const RESTORE_UNKNOWN_TEXT =
  'Sensitive Guard: this placeholder is not available in the current process. Enable pii.restore before the redaction that minted it.'

export function restoreExistsText(file: string): string {
  return 'Sensitive Guard: ' + file + ' already exists; choose a new path.'
}

export function restoreWriteFailedText(file: string): string {
  return 'Sensitive Guard: could not write ' + file + '. Check the path and permissions.'
}

export function restoreSuccessText(placeholder: string, file: string): string {
  return 'Sensitive Guard: restored ' + placeholder + ' to ' + file + ' (mode 0600, no overwrite).'
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
