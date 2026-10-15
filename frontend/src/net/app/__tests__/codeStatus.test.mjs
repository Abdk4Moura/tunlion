// node frontend/src/net/app/__tests__/codeStatus.test.mjs
import { codeStatusAfterTransfer } from '../codeStatus.js'

let ok = true
const eq = (label, got, want) => {
  if (got !== want) { console.log(`  !! ${label}: got ${got} want ${want}`); ok = false }
  else console.log(`  ${label}: OK`)
}
const done = { direction: 'receive', status: 'complete' }
eq('the code receive finished: received', codeStatusAfterTransfer('connected', done, true), 'received')
eq('still transferring: keep waiting', codeStatusAfterTransfer('connected', { direction: 'receive', status: 'transferring' }, true), 'connected')
eq('a remembered device sent it: not the code box', codeStatusAfterTransfer('connected', done, false), 'connected')
eq('an error stays', codeStatusAfterTransfer('the other device left', done, true), 'the other device left')
eq('our own send completing changes nothing', codeStatusAfterTransfer('connected', { direction: 'send', status: 'complete' }, true), 'connected')
if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
