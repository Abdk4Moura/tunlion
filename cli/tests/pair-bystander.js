// CLI `join <code>` pairs with the browser that showed the code, never with a
// bystander browser in the same room. Driven by pair-bystander-gates.sh.
//
//   node pair-bystander.js <app-url> <tunlion-bin> <server> <work-dir> [rounds]
//
// A browser that makes a code sits in its network's room, and everyone else on
// that network is in the room too. The claiming CLI links every peer in the
// room, and used to bind its ceremony to whichever link came up first: when
// that was a bystander, its SPAKE2 element went to the bystander, the creator
// never heard from it, and the pairing stalled (2 in about 40 matrix pairings).
//
// To make the bad order certain instead of occasional, the creator page's
// incoming `signal` frames are held back for CREATOR_SIGNAL_DELAY_MS once its
// code is shown: the CLI's link to the bystander (already in the room, not
// delayed) is then up seconds before its link to the creator. The setup check
// below asserts that order, so a pass is never a pass of the easy case.
const path = require('path')
const cp = require('child_process')
const fs = require('fs')
const { chromium } = require(process.env.PLAYWRIGHT_MODULE ||
  path.join(__dirname, '..', '..', 'frontend', 'node_modules', 'playwright'))

const [, , appUrl, bin, server, work, roundsArg] = process.argv
const ROUNDS = Number(roundsArg) || 3
const DELAY = Number(process.env.CREATOR_SIGNAL_DELAY_MS || 4000)
const CODE = /\b[a-z]+-[a-z]+(?:-[a-z]+)?-\d{2,5}\b/
const say = (s) => console.log(s)

async function openPage(b, holdSignals) {
  const ctx = await b.newContext({ serviceWorkers: 'block', viewport: { width: 1280, height: 860 } })
  const st = { hold: false }
  if (holdSignals) {
    await ctx.routeWebSocket(/socket\.io/, (ws) => {
      const srv = ws.connectToServer()
      ws.onMessage((m) => srv.send(m))
      srv.onMessage((m) => {
        if (st.hold && typeof m === 'string' && m.startsWith('42["signal"')) setTimeout(() => ws.send(m), DELAY)
        else ws.send(m)
      })
    })
  }
  const p = await ctx.newPage()
  await p.goto(appUrl, { waitUntil: 'networkidle' })
  await p.waitForTimeout(2500)
  const name = await p.evaluate(() => sessionStorage.getItem('tunlion.name'))
  return { ctx, p, st, name }
}

function runJoin(dir, code) {
  return new Promise((res) => {
    const env = { ...process.env, HOME: dir, TUNLION_CONFIG_DIR: dir, TUNLION_NONINTERACTIVE: '1' }
    const ch = cp.spawn(bin, ['--server', server, 'join', code], { env })
    let out = ''
    ch.stdout.on('data', (d) => (out += d))
    ch.stderr.on('data', (d) => (out += d))
    const t = setTimeout(() => ch.kill('SIGKILL'), 75000)
    ch.on('close', (rc) => { clearTimeout(t); res({ rc, out }) })
  })
}

;(async () => {
  const b = await chromium.launch({ args: ['--disable-features=WebRtcHideLocalIpsWithMdns'] })
  let fail = 0
  try {
    const by = await openPage(b, false)
    say(`bystander in the room: ${by.name}`)
    for (let i = 1; i <= ROUNDS; i++) {
      const dir = path.join(work, `r${i}`)
      fs.mkdirSync(dir, { recursive: true })
      cp.execFileSync(bin, ['init', '--name', `claimer${i}`, '--recovery-file', path.join(dir, 'rec.txt'), '--yes'],
        { env: { ...process.env, HOME: dir, TUNLION_CONFIG_DIR: dir }, stdio: 'ignore' })
      const cr = await openPage(b, true)
      await cr.p.getByRole('radio', { name: 'Remember a device' }).click()
      await cr.p.getByRole('button', { name: 'Create a code' }).click()
      await cr.p.waitForTimeout(2000)
      const code = ((await cr.p.innerText('body')).match(CODE) || [])[0]
      if (!code) { say(`FAIL: P${i} the creator page showed no code`); fail++; await cr.ctx.close(); continue }
      cr.st.hold = true
      const joined = runJoin(dir, code)
      const rem = cr.p.getByRole('button', { name: 'Remember', exact: true }).first()
      const offered = await rem.waitFor({ state: 'visible', timeout: 45000 }).then(() => true, () => false)
      if (offered) await rem.click()
      const { rc, out } = await joined
      fs.writeFileSync(path.join(work, `join-${i}.log`), out)
      const links = [...out.matchAll(/^\s*\S+\s+(\S+)\s*$/gm)].map((m) => m[1])
        .filter((n) => n === by.name || n === cr.name)
      // Setup check: the bad order happened (the bystander linked first).
      if (links[0] !== by.name) {
        say(`FAIL: P${i} setup: the CLI's first link was not the bystander (links: ${links.join(', ') || 'none'})`)
        fail++
      } else if (!offered || rc !== 0 || !out.includes(`remembered as '${cr.name}'`)) {
        say(`FAIL: P${i} join ${code} with ${by.name} linked first: offered=${offered} rc=${rc}`)
        say(out.split('\n').slice(-6).join('\n'))
        fail++
      } else {
        say(`PASS: P${i} join paired with the code's browser (${cr.name}), not the bystander (${by.name}) that linked first`)
      }
      await cr.ctx.close()
    }
  } finally {
    await b.close()
  }
  process.exit(fail ? 1 : 0)
})().catch((e) => { console.error('FAIL: harness', String(e).slice(0, 300)); process.exit(1) })
