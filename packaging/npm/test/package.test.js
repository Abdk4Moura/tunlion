'use strict'
// Packaging-shape tests for @abdk4moura/filament-cli. No network, no Rust, no
// postinstall: the launcher is exercised against a fake vendor binary.
const assert = require('node:assert/strict')
const { spawnSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')

const PKG = path.join(__dirname, '..')
const pkg = require(path.join(PKG, 'package.json'))

test('package exposes tunlion and tl through the same launcher', () => {
  assert.equal(pkg.bin.tunlion, 'bin/tunlion.js')
  assert.equal(pkg.bin.tl, pkg.bin.tunlion)
  const launcher = path.join(PKG, pkg.bin.tunlion)
  assert.ok(fs.existsSync(launcher), `${launcher} must exist`)
  assert.match(fs.readFileSync(launcher, 'utf8'), /^#!\/usr\/bin\/env node\n/)
})

test('launcher forwards argv, stdio and the exit code', { skip: process.platform === 'win32' }, () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tunlion-npm-test-'))
  try {
    // Mirror the published layout so the launcher's relative requires resolve
    // exactly as they do after `npm i -g`.
    fs.mkdirSync(path.join(tmp, 'bin'))
    fs.cpSync(path.join(PKG, 'bin', 'tunlion.js'), path.join(tmp, 'bin', 'tunlion.js'))
    fs.cpSync(path.join(PKG, 'scripts'), path.join(tmp, 'scripts'), { recursive: true })
    fs.mkdirSync(path.join(tmp, 'vendor'))
    const vendor = path.join(tmp, 'vendor', 'tunlion')
    fs.writeFileSync(
      vendor,
      '#!/bin/sh\nprintf "argv:%s\\n" "$*"\nexit 7\n',
      { mode: 0o755 }
    )

    const r = spawnSync(process.execPath, [path.join(tmp, 'bin', 'tunlion.js'), 'send', 'a b', '--code'], {
      encoding: 'utf8'
    })
    assert.equal(r.status, 7)
    assert.equal(r.stdout, 'argv:send a b --code\n')
    assert.equal(r.stderr, '')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})
