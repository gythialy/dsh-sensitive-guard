/**
 * Outbound URL heuristics for the network layer. URLs are parsed locally; no
 * DNS lookup or request is ever made, and returned reasons never echo them.
 * @module dsh-sensitive-guard/policy/network
 */
import type { GuardAction } from '../contracts.js'

/** Credential-like query parameter names from the design document. */
const CREDENTIAL_QUERY = /^(?:token|key|secret|password|passwd|sig|signature|auth)$/i

export interface NetworkFinding {
  kind: 'userinfo' | 'credential-query'
  action: GuardAction
}

/**
 * Scan URL strings. Embedded userinfo always denies; a credential-like query
 * parameter yields the configured `network.default`. The first userinfo URL
 * wins over any query finding.
 */
export function detectNetworkFinding(
  urls: readonly string[],
  defaultAction: GuardAction,
): NetworkFinding | undefined {
  let hasCredentialQuery = false
  for (const raw of urls) {
    let url: URL
    try {
      url = new URL(raw)
    } catch {
      continue
    }
    if (url.username.length > 0 || url.password.length > 0) {
      return { kind: 'userinfo', action: 'deny' }
    }
    if (!hasCredentialQuery) {
      for (const name of url.searchParams.keys()) {
        if (CREDENTIAL_QUERY.test(name)) {
          hasCredentialQuery = true
          break
        }
      }
    }
  }
  if (hasCredentialQuery) return { kind: 'credential-query', action: defaultAction }
  return undefined
}
