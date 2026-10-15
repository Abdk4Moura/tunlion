// APPLICATION layer: whether the page looks for the optional LAN-discovery
// helper (experiments/localsend-discovery) on 127.0.0.1.
//
// Off unless asked for. Probing it on every load logged a refused-connection
// error for every visitor, and a public page reaching into the visitor's own
// machine is exactly what browsers now put behind a local-network permission
// prompt. Turn it on with ?helper=1 (remembered) or
// localStorage.tunlionLocalHelper = '1'; ?helper=0 turns it off again.
export function localHelperEnabled(search, stored) {
  let q = null
  try { q = new URLSearchParams(search || '').get('helper') } catch {}
  if (q === '1') return { enabled: true, remember: '1' }
  if (q === '0') return { enabled: false, remember: '0' }
  return { enabled: stored === '1', remember: null }
}
