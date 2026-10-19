import { rm } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
for (const dir of ['lib', 'coverage']) {
  await rm(new URL(dir + '/', 'file://' + root), { recursive: true, force: true })
}
