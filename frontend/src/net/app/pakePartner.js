// APPLICATION layer: who a code ceremony runs with (the browser half of the
// CLI's pake_ceremony::partner_for; keep the two in step).
//
// Everyone on the same network shares a room, so the first link that comes up
// after a code is made or claimed can be a bystander (another tab, another
// device on the Wi-Fi). The ceremony was bound to it, the real partner never
// heard from us, and pairing stalled about one time in four. The real partner's
// element names our nameplate (`np`), so it identifies the right peer.
//   bound   the peer the ceremony is bound to (null: none yet)
//   from    who sent this PAKE payload
//   isMsg   it is a pake-msg (an element), not a pake-confirm
//   np      the payload's nameplate (undefined from an old peer: treated as ours)
//   ourNp   our ceremony's nameplate
//   haveK   our ceremony already derived K (then it is committed)
// Returns 'ours' (feed it), 'switch' (rebind to `from`, send our element
// again) or 'ignore'.
export function pakePartnerFor({ bound, from, isMsg, np, ourNp, haveK }) {
  if (np != null && ourNp != null && np !== ourNp) return 'ignore'
  if (!bound || bound === from) return 'ours'
  if (isMsg && np != null && np === ourNp && !haveK) return 'switch'
  return 'ignore'
}
