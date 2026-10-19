/**
 * Public policy-engine surface. Hooks only need `createPolicyEngine`;
 * `loadRuleSet` and `clearPolicyCache` exist for startup validation and tests.
 * @module dsh-sensitive-guard/policy
 */
export { createPolicyEngine } from './evaluator.js'
export type { PolicyEngineOptions } from './evaluator.js'
export { clearPolicyCache, loadRuleSet } from './rules.js'
export type { LoadRuleSetOptions } from './rules.js'
export type { CompiledRule, LoadedRuleSet, Rule, RuleArgv, RuleMatch, RuleWhen } from './types.js'
