#!/usr/bin/env node
'use strict'
// Thin launcher: exec the real tunlion binary (downloaded into ./vendor by the
// postinstall) with the same args, stdio, and exit code.
const { spawnSync } = require('child_process')
const fs = require('fs')
const { binaryPath } = require('../scripts/paths')

const bin = binaryPath()
if (!fs.existsSync(bin)) {
  console.error('tunlion: binary missing — reinstall with `npm i -g filament-cli`,')
  console.error('or install another way: https://tunlion.autumated.com')
  process.exit(1)
}

const r = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' })
if (r.error) {
  console.error(`tunlion: failed to run binary — ${r.error.message}`)
  process.exit(1)
}
process.exit(r.status === null ? 1 : r.status)
