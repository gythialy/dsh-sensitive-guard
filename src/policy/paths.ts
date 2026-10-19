/**
 * Path evidence normalization: `~` and whitelisted environment expansion,
 * cwd-relative resolution, and symlink protection by matching both the
 * normalized path and its `realpath`.
 * @module dsh-sensitive-guard/policy/paths
 */
import { realpathSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

/** Only these variables are expanded; arbitrary input never triggers env reads. */
const ENV_WHITELIST = new Set(['HOME', 'PWD', 'USER', 'TMPDIR', 'DSH_HOME'])

const ENV_PATTERN = /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g

/** Expand a leading `~` using `$HOME` (or the OS home) . */
export function expandHome(input: string, env: NodeJS.ProcessEnv = process.env): string {
  if (!input.startsWith('~')) return input
  const home = env.HOME ?? env.USERPROFILE ?? os.homedir()
  if (input === '~') return home
  if (input.startsWith('~/') || input.startsWith('~\\')) return home + '/' + input.slice(2)
  return input
}

/** Expand `$NAME` and `${NAME}` for whitelisted variables only. */
export function expandEnvVars(input: string, env: NodeJS.ProcessEnv = process.env): string {
  return input.replace(
    ENV_PATTERN,
    (whole, braced: string | undefined, plain: string | undefined) => {
      const name = braced ?? plain
      if (name === undefined || !ENV_WHITELIST.has(name)) return whole
      const value = env[name]
      return value === undefined ? whole : value
    },
  )
}

/** Expand home first, then whitelisted variables. */
export function expandPathString(input: string, env: NodeJS.ProcessEnv = process.env): string {
  return expandEnvVars(expandHome(input, env), env)
}

/** Path flavor used for resolution; lets Windows rules be unit-tested anywhere. */
export function pathApi(platform: NodeJS.Platform): typeof path.win32 {
  return platform === 'win32' ? path.win32 : path.posix
}

/** Windows matching uses forward slashes; other platforms are left alone. */
export function toMatchForm(input: string, platform: NodeJS.Platform): string {
  return platform === 'win32' ? input.replaceAll('\\', '/') : input
}

function relativeWithin(api: typeof path.win32, cwd: string, target: string): string | undefined {
  const relative = api.relative(cwd, target)
  if (relative === '' || relative === '.') return undefined
  if (relative === '..' || relative.startsWith('..' + api.sep) || api.isAbsolute(relative)) {
    return undefined
  }
  return relative
}

function realpathOf(target: string): string | undefined {
  try {
    return realpathSync(target)
  } catch {
    return undefined
  }
}

export interface PathCandidateOptions {
  cwd: string
  platform: NodeJS.Platform
  env?: NodeJS.ProcessEnv
}

/**
 * Every string a path glob may be matched against:
 * - the normalized absolute path,
 * - its cwd-relative form (so relative patterns work),
 * - the `realpath` of an existing path and that path relative to cwd
 *   (so a symlink cannot hide a sensitive target).
 * The candidate list is deduplicated; non-existent paths fall back to the
 * normalized absolute form only.
 */
export function pathCandidates(raw: string, options: PathCandidateOptions): string[] {
  const env = options.env ?? process.env
  const api = pathApi(options.platform)
  const expanded = expandPathString(raw, env)
  const cwd = api.isAbsolute(options.cwd)
    ? api.normalize(options.cwd)
    : api.resolve(process.cwd(), options.cwd)
  const absolute = api.isAbsolute(expanded) ? api.normalize(expanded) : api.resolve(cwd, expanded)

  const candidates = new Set<string>()
  const add = (candidate: string): void => {
    candidates.add(toMatchForm(api.normalize(candidate), options.platform))
  }
  add(absolute)
  const relative = relativeWithin(api, cwd, absolute)
  if (relative !== undefined) add(relative)

  const real = realpathOf(absolute)
  if (real !== undefined) {
    const normalizedReal = api.normalize(real)
    if (normalizedReal !== absolute) add(normalizedReal)
    const realRelative = relativeWithin(api, cwd, normalizedReal)
    if (realRelative !== undefined) add(realRelative)
  }
  return [...candidates]
}
