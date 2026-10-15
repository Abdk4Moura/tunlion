// node frontend/src/net/app/__tests__/accept.test.mjs
// Pins which incoming offers the browser accepts without a click.
import { shouldAutoAccept, offersCoveredNow } from '../accept.js'
import { readFileSync } from 'node:fs'

let ok = true
const eq = (label, got, want) => {
  if (got !== want) { console.log(`  !! ${label}: got ${got} want ${want}`); ok = false }
  else console.log(`  ${label}: OK`)
}
const offer = { direction: 'receive', status: 'offered' }
eq('receive by code', shouldAutoAccept({ ...offer, byCode: true }), true)
eq('a remembered device that proved itself', shouldAutoAccept({ ...offer, provenKnown: true }), true)
eq('a stranger in the room asks', shouldAutoAccept({ ...offer }), false)
eq('claimed but unproven asks', shouldAutoAccept({ ...offer, provenKnown: false, byCode: false }), false)
eq('our own send is never accepted here', shouldAutoAccept({ direction: 'send', status: 'offered', provenKnown: true }), false)
eq('only an offer, not a running transfer', shouldAutoAccept({ direction: 'receive', status: 'transferring', provenKnown: true }), false)
// An offer that landed before the consent: re-checked when the consent lands.
const early = [{ id: 'a', ...offer }, { id: 'b', direction: 'receive', status: 'transferring' }, { id: 'c', direction: 'send', status: 'offered' }]
eq('code consent covers the early offer only', offersCoveredNow(early, { byCode: true }).join(','), 'a')
eq('proof covers the early offer only', offersCoveredNow(early, { provenKnown: true }).join(','), 'a')
eq('no consent, nothing accepted', offersCoveredNow(early, {}).length, 0)
// Both consent paths must re-check offers that arrived first (B01/B02: the
// receive-by-code path did not, so a CLI sender that offered before the
// browser finished the ceremony waited forever).
const hook = readFileSync(new URL('../../../lib/useTunlion.js', import.meta.url), 'utf8')
const eph = hook.slice(hook.indexOf('if (pendingPakeRef.current?.ephemeral)'), hook.indexOf("tel('pake-transfer-authed'"))
eq('receive by code re-checks early offers', /offersCoveredNow\([\s\S]{0,80}byCode: true/.test(eph), true)
eq('pair-proof re-checks early offers', /offersCoveredNow\([\s\S]{0,80}provenKnown: true/.test(hook), true)
if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
