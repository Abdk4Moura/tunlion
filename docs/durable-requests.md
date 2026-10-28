# Durable transfer requests: first engine slice

Status: storage foundation, daemon receive adapter, request commands and explicit
sender-retained retries verified on an isolated leased worker. Not deployed; not
merged; no production daemon or installed binary was changed.

`--defer` is an opt-in async mode. Ordinary sends keep their existing
exit-0-means-delivered contract. For `--defer`, exit 0 with `state:"waiting"`
means accepted and retained, never delivered. A closed non-delivery exits
non-zero and `delivered:false`.

## Integration contract

- Retention is explicit: `send --defer --to <device>` snapshots payloads in a
  private, bounded local outbox before making a network attempt. Existing sends
  and their exit/history contract remain unchanged.
- `send --resume <offer>` reuses the exact snapshot and stable offer identity.
  Queued results have `state: waiting` and `delivered: false`, not delivery success.
  The CLI daemon schedules due offers with the existing sender executable and
  reaps its owned child on shutdown. No idle-daemon or cloud delivery is implied.
- Durable offers carry an explicit `request` marker. An older ordinary offer is
  not silently reinterpreted as this protocol. A capable receiver returns a
  manifest-bound pending receipt; approval and delivery remain separate.
- `requests accept <id>` / `requests decline <id>` address incoming file offers.
  Existing `approve` / `deny` keep their capability-consent meaning. Incoming
  storage is under `transfer-requests`, separate from legacy `requests.json`.
- An approved destination is one exact file below the receive root, not an
  arbitrary path or archive extraction grant. A multi-path send currently creates
  separate one-file offers; a directory snapshot is one tar object, not an
  approved expanded tree.
- The pairing PR and its preview are separate from this backend branch. Neither
  integration authorizes deployment or production daemon changes.

## Scope

`crates/filament-peerloop/src/recv/requests.rs` owns the receiver-side record for
an asynchronous file offer. It answers four questions without touching the
network, the terminal or file placement:

1. Is this exact manifest well formed and safe to store?
2. Is the sender, as observed *now*, allowed to create or advance this request?
3. What decision and destination are durably recorded for that exact digest?
4. What authoritative snapshot should a client see after a restart?

It deliberately does not deliver bytes, approve capabilities, or promise that an
offline sender will return.

## Encoded rules

- A manifest has 1..=256 entries with relative, traversal-free paths and a
  mandatory lower-case 64-hex SHA-256 per entry. Entries are sorted, duplicate
  and case-fold duplicate paths are refused, and total bytes/metadata are
  bounded.
- The digest covers `path`, `size` and `sha256` only. `mtime` is display
  metadata and cannot change the reviewed agreement.
- A record is one exact offer id plus manifest. Reusing an offer id with a
  different sender or digest is refused. A fulfilled/denied/expired record that
  has been pruned leaves a tombstone so the id cannot be replayed.
- States are `pending`, `approved` (accepted; waiting for the sender),
  `delivering`, `denied`, `expired`, `fulfilled`, `failed`, `withdrawn`.
  `approved` never means bytes arrived.
- Owned devices auto-approve only when the caller supplies a destination.
  Delegated/joined devices are signed by the owner user key but are not owned
  devices: they stay pending for review. "External" here means not an owner
  device, not "different user key".
- Acceptance binds the exact manifest digest and a destination string.
  Destination confinement to receive roots remains the caller's policy.
- Every write requires a fresh `SenderIdentity` observation, including
  idempotent retries of accept, begin-delivery and complete. A revoked,
  unverified, unknown or expired sender is refused even if acceptance succeeded
  earlier. Stored sender fields are a snapshot, not a capability.
- Mutations are revision-checked. The store is written atomically under a
  cross-process lock. A mutation returns its notification event only after the
  commit; there is no notification inside the store.
- Snapshots are full authoritative snapshots. A cursor below the retained
  terminal floor reports `resync_required`. There is no event log or mailbox.
- Terminal records and tombstones are bounded by monotonic revision, not wall
  clock, so a clock step cannot lose a just-written receipt. Zero retention is
  refused at open. Aggregate serialized manifest bytes are capped as well as
  entry count/pending count. No record contains grants or capability lists, so
  accepting an offer creates no standing access.
- The acceptance deadline gates review and starting delivery; an already
  `delivering` transfer may finish and be receipted after it. `failed` and
  `withdrawn` are terminal transitions for local failure and owner cancellation.
- Path validation also refuses Windows device names, trailing dot/space
  segments and Windows-forbidden characters. NFC/NFD collisions remain for the
  later placement slice.

## Delivery mechanics

- A durable offer is held until the sender's device-key possession is Proven.
  Shadow-mode receivers issue that challenge only for this explicit protocol.
- The receiver stages bytes in `.tunlion-request-<id>.part`, hashes them, and
  rechecks authority before placement. Final placement is a no-overwrite hard
  link to the exact approved path.
- The receipt is committed before the delivery acknowledgement. If acknowledgement
  is lost, the sender's retry sees `fulfilled`, the receiver re-acks, and no
  second file is placed. On Unix, recovery requires the request-specific staged
  artifact by device/inode identity, not merely a file with a matching hash.
  Non-Unix hosts refuse hash-only recovery and never delete a destination on
  that basis; they require a fresh transfer after a crash.
- Writer chunks recheck authority at a bounded interval (2s), and placement
  always rechecks immediately before the link.
- Approval reserves space against other active deliveries with a free-space
  sample taken under the store lock. This is a bound, not an atomic guarantee
  against every external writer on the filesystem.
- A transport without `full` SHA-256 is refused for durable admission. A plain
  daemon offer without the `request` marker keeps the legacy path unchanged.

## Deliberately not in this slice

- Cancel is sender-local: it stops retries and deletes the private snapshot, but
  does not claim the receiver withdrew the request. The receiver record expires
  within 7 days.
- Multi-file transport grouping is one request per file. A directory is a single
  tar object, not an approved expanded tree.
- Core exposes no request UI yet, and `CoreHost::free_space` returns `None`, so
  Core does not get the free-space reservation bound.
- Full per-file history across a multi-offer retained send; ordinary history
  remains terminal one-shot.
- NFC/NFD collision hardening for eventual file placement.
- Playwright/dashboard/Core request surfaces.

## Verification

Isolated worker, source snapshot archived with per-file SHA-256, debug
`test-hooks` binary. `runner/durable-requests-e2e.py` bootstraps a job-local
Python venv from `backend/requirements.txt` when `--python` is omitted, so a
bare worker can reproduce the gate without hand-installed Flask/Eventlet.

- full `filament-peerloop` library: **525 passed**
- `filament-cli` bin tests: **804 passed**, 2 ignored
- focused request store: **20 passed**
- retained sender store: **10 passed**
- real network/restart E2E: proven restricted sender created a pending offer with
  no bytes; daemon approval plus receiver restart delivered the exact retained
  snapshot; completed retry made no duplicate; decline never delivered; the
  sender daemon retried a retained offer; an offline receiver did not lose the
  offer; an acknowledgement-loss retry reused the committed receipt with no
  duplicate placement; fresh certificate revocation defeated a prior approval.
- the gate boots with the configured drop dir deliberately different from the
  daemon's `up --dir`, proving approval uses the served inbox recorded in
  `up.inbox`.
- evidence: worker `results/durable-e2e-review-20261021T123107`, sanitized logs
  archived locally. The gate bootstraps its own backend venv.
- the E2E is wired into CI as its own job, not a manual-only script; it requires
  `--fault-hooks` and asserts the sender/receiver terminal states, not just the
  absence of a duplicate file.

The Python request model remains a policy simulation, not this Rust runtime.
