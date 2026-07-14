'use strict'
// Shared helpers for locating the downloaded binary.
const path = require('path')

function binaryName() {
  return process.platform === 'win32' ? 'filament.exe' : 'filament'
}

// The postinstall downloads the platform binary here; the bin/ launcher execs it.
function binaryPath() {
  return path.join(__dirname, '..', 'vendor', binaryName())
}

module.exports = { binaryName, binaryPath }
