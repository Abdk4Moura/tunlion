'use strict'
// Downloads the prebuilt filament binary matching THIS package's version from
// the GitHub release, verifies its SHA-256 against the release SHA256SUMS, and
// unpacks it into ./vendor. Mirrors scripts/install.sh. Zero runtime deps.
//
// The npm package version === the CLI release version (set at publish time), so
// `npm i -g filament-cli@X.Y.Z` fetches the `cli-vX.Y.Z` assets.

const https = require('https')
const fs = require('fs')
const path = require('path')
const os = require('os')
const crypto = require('crypto')
const { execFileSync } = require('child_process')
const { version } = require('../package.json')
const { binaryName, binaryPath } = require('./paths')

const REPO = 'Abdk4Moura/filament'
const TAG = `cli-v${version}`

// platform/arch -> { release target triple, archive extension }
function target() {
  const p = process.platform
  const a = process.arch
  if (p === 'linux' && a === 'x64') return { t: 'x86_64-unknown-linux-musl', ext: 'tar.gz' }
  if (p === 'darwin' && a === 'arm64') return { t: 'aarch64-apple-darwin', ext: 'tar.gz' }
  if (p === 'darwin' && a === 'x64') return { t: 'x86_64-apple-darwin', ext: 'tar.gz' }
  // Windows ships an x64 build; it runs natively on x64 and via emulation on ARM64.
  if (p === 'win32' && (a === 'x64' || a === 'arm64')) return { t: 'x86_64-pc-windows-msvc', ext: 'zip' }
  return null
}

// GET that follows redirects and resolves to a Buffer.
function get(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': 'filament-cli-npm' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume()
          return resolve(get(res.headers.location))
        }
        if (res.statusCode !== 200) {
          res.resume()
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`))
        }
        const chunks = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => resolve(Buffer.concat(chunks)))
      })
      .on('error', reject)
  })
}

function extract(archive, dest, ext) {
  if (ext === 'zip' && process.platform === 'win32') {
    // PowerShell is always present on Windows; more reliable than assuming bsdtar.
    execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', `Expand-Archive -LiteralPath '${archive}' -DestinationPath '${dest}' -Force`], { stdio: 'ignore' })
  } else {
    // bsdtar/GNU tar extracts .tar.gz everywhere and .zip on modern systems.
    execFileSync('tar', ['-xf', archive, '-C', dest], { stdio: 'ignore' })
  }
}

async function main() {
  const tgt = target()
  if (!tgt) {
    console.error(`filament: no prebuilt binary for ${process.platform}/${process.arch}.`)
    console.error('Install another way: https://filament.autumated.com  or  cargo install filament-cli')
    process.exit(1)
  }
  const asset = `filament-${tgt.t}.${tgt.ext}`
  const base = `https://github.com/${REPO}/releases/download/${TAG}`
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'filament-'))
  try {
    const [bin, sums] = await Promise.all([get(`${base}/${asset}`), get(`${base}/SHA256SUMS`)])

    const got = crypto.createHash('sha256').update(bin).digest('hex').toLowerCase()
    const line = sums
      .toString('utf8')
      .split('\n')
      .find((l) => l.includes(asset))
    if (!line) throw new Error(`no checksum for ${asset} in SHA256SUMS`)
    const want = line.trim().split(/\s+/)[0].toLowerCase()
    if (got !== want) throw new Error(`checksum mismatch (got ${got}, want ${want})`)

    const archive = path.join(tmp, asset)
    fs.writeFileSync(archive, bin)
    extract(archive, tmp, tgt.ext)

    const vendor = path.join(__dirname, '..', 'vendor')
    fs.mkdirSync(vendor, { recursive: true })
    fs.copyFileSync(path.join(tmp, binaryName()), binaryPath())
    if (process.platform !== 'win32') fs.chmodSync(binaryPath(), 0o755)
    console.log(`filament: installed ${TAG} for ${tgt.t}`)
  } catch (e) {
    console.error(`filament: install failed — ${e.message}`)
    console.error('Install another way: https://filament.autumated.com  or  cargo install filament-cli')
    process.exit(1)
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
}

main()
