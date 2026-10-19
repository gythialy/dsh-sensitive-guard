import os from 'node:os'
import path from 'node:path'

/** Expand a leading `~/` (or bare `~`) to the current home directory. */
export function expandHome(input: string, home = os.homedir()): string {
  if (input === '~') return home
  if (input.startsWith('~/') || input.startsWith('~' + path.sep)) {
    return path.join(home, input.slice(2))
  }
  return input
}

/** `$DSH_HOME` when the host sets it, otherwise `~/.dsh`. */
export function dshHome(env: NodeJS.ProcessEnv = process.env, home = os.homedir()): string {
  return env.DSH_HOME && env.DSH_HOME.length > 0 ? env.DSH_HOME : path.join(home, '.dsh')
}

/** Resolve a configured path against the session cwd, expanding `~`. */
export function resolveConfiguredPath(input: string, cwd: string, home = os.homedir()): string {
  const expanded = expandHome(input, home)
  return path.isAbsolute(expanded) ? path.normalize(expanded) : path.resolve(cwd, expanded)
}
