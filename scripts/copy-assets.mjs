import { cp, mkdir } from 'node:fs/promises'
import { readdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const root = fileURLToPath(new URL('..', import.meta.url))
const srcDir = path.join(root, 'src')
const outDir = path.join(root, 'lib')

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true })
  const files = []
  for (const entry of entries) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) files.push(...(await walk(full)))
    else files.push(full)
  }
  return files
}

for (const file of await walk(srcDir)) {
  if (!/\.(ya?ml)$/.test(file)) continue
  const target = path.join(outDir, path.relative(srcDir, file))
  await mkdir(path.dirname(target), { recursive: true })
  await cp(file, target)
}
