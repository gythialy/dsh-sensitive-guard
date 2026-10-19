/**
 * First-match rule evaluation over collected evidence. Rules are ANDed across
 * dimensions and ORed inside each; a rule with no evidence dimension never
 * matches. Load or evaluation failures produce a fail-closed decision instead
 * of throwing at tool-call time.
 * @module dsh-sensitive-guard/policy/evaluator
 */
import type { GuardConfig } from '../config.js'
import type { PolicyDecision, PolicyEngine, PolicyInput } from '../contracts.js'
import { commandBasename, type ParsedArgv } from './argv.js'
import { collectEvidence, type PolicyEvidence } from './evidence.js'
import { detectNetworkFinding, type NetworkFinding } from './network.js'
import { loadRuleSet } from './rules.js'
import type { CompiledArgv, CompiledRule, LoadedRuleSet } from './types.js'

const EVALUATION_FAILURE_REASON = 'sensitive-guard: policy evaluation failed'

const NETWORK_REASONS: Record<NetworkFinding['kind'], string> = {
  userinfo:
    'sensitive-guard: outbound URLs with embedded credentials are blocked; remove the credentials and use a secret store',
  'credential-query':
    'sensitive-guard: outbound URLs carrying credential-like query parameters need confirmation',
}

function argvMatches(spec: CompiledArgv, argv: ParsedArgv): boolean {
  if (spec.command.length > 0) {
    // Match both the literal word and its base name so /bin/rm counts as rm.
    const variants = new Set([argv.command, commandBasename(argv.command)])
    let matched = false
    for (const variant of variants) {
      if (spec.command.some((matcher) => matcher(variant))) {
        matched = true
        break
      }
    }
    if (!matched) return false
  }

  if (spec.args.length > 0) {
    if (argv.args.length < spec.args.length) return false
    for (let index = 0; index < spec.args.length; index += 1) {
      if (!spec.args[index]!(argv.args[index]!)) return false
    }
  }

  if (spec.anyArg.length > 0) {
    let found = false
    for (const token of argv.anyTokens) {
      if (spec.anyArg.some((matcher) => matcher(token))) {
        found = true
        break
      }
    }
    if (!found) return false
  }

  // Every negated pattern must hold: no token may match it.
  if (spec.notAnyArg.length > 0) {
    for (const token of argv.anyTokens) {
      if (spec.notAnyArg.some((matcher) => matcher(token))) return false
    }
  }

  if (spec.pipeline.length > 0) {
    if (!spec.pipeline.some((matcher) => matcher(argv.pipeline))) return false
  }

  return true
}

/**
 * True when one compiled rule matches the evidence. `match.when.platform` is a
 * precondition, not evidence: a rule that only restricts platforms still never
 * matches on its own.
 */
export function ruleMatches(rule: CompiledRule, evidence: PolicyEvidence): boolean {
  const match = rule.match
  const constrained =
    match.tools.length > 0 ||
    match.params.length > 0 ||
    match.paths.length > 0 ||
    match.argv !== undefined ||
    match.agents.length > 0
  if (!constrained) return false

  if (match.platforms !== undefined && !match.platforms.includes(evidence.platform)) {
    return false
  }

  if (match.tools.length > 0 && !match.tools.some((matcher) => matcher(evidence.tool))) {
    return false
  }

  if (match.agents.length > 0) {
    const agentId = evidence.agentId
    if (agentId === undefined || !match.agents.some((matcher) => matcher(agentId))) {
      return false
    }
  }

  if (
    match.paths.length > 0 &&
    !evidence.paths.some((path) => match.paths.some((matcher) => matcher(path)))
  ) {
    return false
  }

  for (const param of match.params) {
    const values = evidence.params.get(param.key)
    if (
      values === undefined ||
      !values.some((value) => param.patterns.some((matcher) => matcher(value)))
    ) {
      return false
    }
  }

  if (match.argv !== undefined && !evidence.argvs.some((argv) => argvMatches(match.argv!, argv))) {
    return false
  }

  return true
}

function ruleDecision(rule: CompiledRule, evidence: PolicyEvidence): PolicyDecision {
  const decision: PolicyDecision = {
    action: rule.action,
    matched: true,
    ruleId: rule.id,
    enforce: rule.enforce,
  }
  const reason = rule.reason
  if (reason !== undefined) decision.reason = reason
  if (evidence.paths.length > 0) decision.paths = evidence.paths
  const command = evidence.commands[0]
  if (command !== undefined) decision.command = command
  return decision
}

function networkDecision(finding: NetworkFinding, evidence: PolicyEvidence): PolicyDecision {
  const decision: PolicyDecision = {
    action: finding.action,
    matched: true,
    ruleId: 'network:' + finding.kind,
    network: true,
    reason: NETWORK_REASONS[finding.kind],
  }
  const command = evidence.commands[0]
  if (command !== undefined) decision.command = command
  return decision
}

export interface PolicyEngineOptions {
  config: GuardConfig
  platform?: NodeJS.Platform
}

/**
 * Build the policy engine. Rules load lazily per `input.cwd`; a load failure is
 * reported as the configured fail-closed decision and never allows the call.
 */
export function createPolicyEngine(options: PolicyEngineOptions): PolicyEngine {
  const config = options.config
  const defaultPlatform = options.platform ?? process.platform
  let lastLoaded: LoadedRuleSet | undefined

  const loadFor = (cwd: string): LoadedRuleSet => {
    const loaded = loadRuleSet({ config, cwd, platform: defaultPlatform })
    lastLoaded = loaded
    return loaded
  }

  return {
    evaluate(input: PolicyInput): PolicyDecision {
      try {
        const platform = input.platform ?? defaultPlatform
        const evidence = collectEvidence(input, platform)
        const finding = config.network.enabled
          ? detectNetworkFinding(evidence.urls, config.network.default)
          : undefined

        // Embedded userinfo is always denied, even if a broad allow rule matches.
        if (finding !== undefined && finding.kind === 'userinfo') {
          return networkDecision(finding, evidence)
        }

        const loaded = loadFor(evidence.cwd)
        for (const rule of loaded.rules) {
          if (ruleMatches(rule, evidence)) return ruleDecision(rule, evidence)
        }

        if (finding !== undefined) return networkDecision(finding, evidence)
        return { action: config.defaultDecision, matched: false }
      } catch {
        return {
          action: config.failClosed ? 'deny' : 'ask',
          matched: false,
          reason: EVALUATION_FAILURE_REASON,
        }
      }
    },

    get ruleCount(): number {
      if (lastLoaded !== undefined) return lastLoaded.rules.length
      try {
        lastLoaded = loadRuleSet({ config, cwd: process.cwd(), platform: defaultPlatform })
        return lastLoaded.rules.length
      } catch {
        return 0
      }
    },
  }
}
