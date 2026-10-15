// APPLICATION layer: what the code box says once a transfer moves.
//
// A receive by code shows "waiting for the file" ('connected') after the code
// is accepted. When that file is in, the box must say so ('received'); it used
// to keep waiting forever. Any other status (an error, a pairing) is left as it
// is, and a transfer that is not this code session's receive changes nothing.
export function codeStatusAfterTransfer(status, t, byCode) {
  if (status !== 'connected') return status
  if (byCode && t && t.direction === 'receive' && t.status === 'complete') return 'received'
  return status
}
