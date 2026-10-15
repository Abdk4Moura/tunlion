// node frontend/src/net/app/__tests__/localHelper.test.mjs
import { localHelperEnabled } from '../localHelper.js'

let ok = true
const eq = (label, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want)
  if (g !== w) { console.log(`  !! ${label}: got ${g} want ${w}`); ok = false }
  else console.log(`  ${label}: OK`)
}
eq('a normal visit does not probe 127.0.0.1', localHelperEnabled('', null).enabled, false)
eq('?helper=1 turns it on and remembers', localHelperEnabled('?helper=1', null), { enabled: true, remember: '1' })
eq('remembered on', localHelperEnabled('', '1').enabled, true)
eq('?helper=0 turns it off and remembers', localHelperEnabled('?helper=0', '1'), { enabled: false, remember: '0' })
if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
