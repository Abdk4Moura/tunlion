// node frontend/src/net/app/__tests__/pakePartner.test.mjs
import { pakePartnerFor } from '../pakePartner.js'

let ok = true
const eq = (label, got, want) => {
  if (got !== want) { console.log(`  !! ${label}: got ${got} want ${want}`); ok = false }
  else console.log(`  ${label}: OK`)
}
const base = { isMsg: true, np: '314', ourNp: '314', haveK: false }
eq('bound to a bystander; the real partner speaks: switch', pakePartnerFor({ ...base, bound: 'desk', from: 'cli' }), 'switch')
eq('from the bound peer: ours', pakePartnerFor({ ...base, bound: 'cli', from: 'cli' }), 'ours')
eq('nobody bound yet: ours', pakePartnerFor({ ...base, bound: null, from: 'cli' }), 'ours')
eq("another code's ceremony: ignore", pakePartnerFor({ ...base, bound: 'cli', from: 'x', np: '999' }), 'ignore')
eq('after K the ceremony is committed', pakePartnerFor({ ...base, bound: 'cli', from: 'desk', haveK: true }), 'ignore')
eq('a confirm from someone else never switches', pakePartnerFor({ ...base, bound: 'cli', from: 'desk', isMsg: false }), 'ignore')
eq('an untagged element from someone else does not switch', pakePartnerFor({ ...base, bound: 'cli', from: 'desk', np: undefined }), 'ignore')
if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
