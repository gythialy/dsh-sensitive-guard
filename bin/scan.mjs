#!/usr/bin/env node
import { main } from '../lib/cli/scan.js'

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code
  })
  .catch((error) => {
    process.stderr.write(
      'sensitive-guard-scan: ' + (error instanceof Error ? error.message : 'scan failed') + '\n',
    )
    process.exitCode = 2
  })
