/**
 * Schemastery configuration schema and defaults. The public defaults follow the
 * design document: observe first (`monitor`), fail closed on evaluation errors,
 * and deny high-risk credential paths by default when enforcement is enabled.
 * @module dsh-sensitive-guard/config
 */
import Schema from '@deepseek-ai/schemastery'
import { DEFAULT_EGRESS_DENY } from './egress/policy.js'

/** Files that are examples, not live credentials, and stay readable by default. */
export const DEFAULT_ALLOW_PATHS = [
  '**/.env.example',
  '**/.env.sample',
  '**/.env.template',
] as const

/** Credential-bearing paths denied by default in `enforce` mode. */
export const DEFAULT_DENY_PATHS = [
  '**/.env',
  '**/.env.*',
  '**/.ssh/**',
  '**/.aws/**',
  '**/.gnupg/**',
  '**/.kube/**',
  '**/.npmrc',
  '**/.netrc',
  '**/*.pem',
  '**/*.key',
  '**/id_rsa*',
  '**/id_ed25519*',
  '**/.dsh/.credentials.yaml',
] as const

export const Config = Schema.object({
  /** Observe only (`monitor`) or enforce decisions (`enforce`). */
  mode: Schema.union(['monitor', 'enforce'] as const).default('monitor'),
  /** Decision when no rule matches. */
  defaultDecision: Schema.union(['ask', 'allow', 'deny'] as const).default('ask'),
  /** Deny (instead of ask) when rule evaluation throws. */
  failClosed: Schema.boolean().default(true),
  redact: Schema.object({
    /** Redact admitted user/context messages at `agent/pre-step`. */
    userMessages: Schema.boolean().default(true),
    /** Redact tool results at `tools/post-execute`. */
    toolResults: Schema.boolean().default(true),
    /** Redact prompt sections, runtime contexts, and variables. */
    systemPrompt: Schema.boolean().default(true),
    /** Redact the durable copy of PTC sub-call logs. */
    ptcLog: Schema.boolean().default(true),
    /** Append a count-only notice message when a step is redacted. */
    notify: Schema.boolean().default(false),
  }),
  levels: Schema.object({
    input: Schema.union(['minimal', 'balanced', 'aggressive'] as const).default('aggressive'),
    output: Schema.union(['minimal', 'balanced', 'aggressive'] as const).default('balanced'),
  }),
  policy: Schema.object({
    /** Project rule file, resolved from the session working directory. */
    rulesFile: Schema.string().default('.dsh/rules.yaml'),
    /** Append the vendored high-risk baseline after user rules. */
    builtin: Schema.boolean().default(true),
    /** Upper bound on loaded rules (user + baseline + generated path rules). */
    maxRules: Schema.natural().default(256),
  }),
  paths: Schema.object({
    deny: Schema.array(Schema.string()).default([...DEFAULT_DENY_PATHS]),
    allow: Schema.array(Schema.string()).default([...DEFAULT_ALLOW_PATHS]),
  }),
  network: Schema.object({
    enabled: Schema.boolean().default(true),
    /** Decision for outbound URLs with credential-like query parameters. */
    default: Schema.union(['ask', 'deny', 'allow'] as const).default('ask'),
  }),
  egress: Schema.object({
    /**
     * Bind the loopback CONNECT guard. Off by default: the seam it fills is
     * DSH's launch-time `HTTPS_PROXY`, so enabling it without wiring the
     * environment variable protects nothing (see `/guard egress status`).
     */
    enabled: Schema.boolean().default(false),
    /** Fixed loopback port; the launch environment must name this exact port. */
    port: Schema.natural().default(41999),
    /** Refuse to mount when `enforce` cannot bind the listener. */
    failClosed: Schema.boolean().default(true),
    /**
     * Decision for a destination that matches no rule. `allow` keeps the guard
     * auditable and quiet (default); `deny` turns the lists into an allowlist.
     */
    unknown: Schema.union(['allow', 'deny'] as const).default('allow'),
    /** Allowed `host` or `host:port` entries; globs are accepted in the host. */
    allow: Schema.array(Schema.string()).default([]),
    /** Denied `host` or `host:port` entries; evaluated before `allow`. */
    deny: Schema.array(Schema.string()).default([...DEFAULT_EGRESS_DENY]),
    /** Optional upstream proxy to chain CONNECT tunnels through. */
    upstream: Schema.string().default(''),
    /** Probe the listener at mount and record the result in the audit log. */
    canary: Schema.boolean().default(true),
  }),
  pii: Schema.object({
    enabled: Schema.boolean().default(true),
    /** Empty means `$DSH_HOME/sensitive-guard-pii.key`. */
    keyFile: Schema.string().default(''),
    /** Reserved for the restore command; unsupported in this version. */
    restore: Schema.boolean().default(false),
  }),
  limits: Schema.object({
    maxScanBytes: Schema.natural().default(4 * 1024 * 1024),
    maxArgsBytes: Schema.natural().default(128 * 1024),
  }),
  audit: Schema.object({
    enabled: Schema.boolean().default(true),
    path: Schema.string().default('~/.dsh/audit/sensitive-guard.jsonl'),
    rotateBytes: Schema.natural().default(5 * 1024 * 1024),
  }),
})

/** Validated, default-filled configuration passed to `apply`. */
export type GuardConfig = ReturnType<typeof Config>

/**
 * Normalize a partial plugin config (tests, loader re-validation) into the
 * complete shape. Invalid values throw here, which is the intended fail-loud
 * startup behaviour.
 */
export function resolveConfig(input?: unknown): GuardConfig {
  return Config((input ?? {}) as never) as GuardConfig
}
