// node frontend/src/net/app/__tests__/accept.test.mjs
// Pins which incoming offers the browser accepts without a click.
import { shouldAutoAccept } from '../accept.js'

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
if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
