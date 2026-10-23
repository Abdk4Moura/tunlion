# Folder adapter handoff

Validated host code: Linux slice exact `8f8d66e5`, remote core08. The Windows
folder-serving and owned-download slice is exact `e121b2ff`; see
[access-agreement-validation.md](access-agreement-validation.md). Both are
**library protocol endpoints**. This branch integrates the recipient CLI folder
UI (browse, preview, caller-destination download) on Linux and Windows. It does
not mount a filesystem or deliver a whole-product result. Windows serves the same
protocol over retained HANDLEs; it does not claim a WinFsp mount.

## Dependencies

After the original access/ceremony chain through `67c4956c`:

- `96ccaad3`: exact reviewed pairing entry helpers and fixtures; released
  `norm_code` is unchanged.
- `1e4db4ac`: folder resource operation tracking, pinned-root serving and
  per-request mount admission, plus confinement/cancellation fixtures.
- `d77e2021`: raw control allocation/depth bounds before JSON parsing. This is
  **not** an upstream event-queue capacity fix.
- `8f8d66e5`: checkpoint documentation. The code above is now validated despite
  the historical `wip` commit subjects.

Do not enable folder UI simply by composing these commits. The recipient adapter
and its real authenticated review/open/read/revoke flow must be implemented and
tested first. Keep the separate real TCP CLI acknowledgement fix intact.

## Host API

In `crates/filament-peerloop/src/access.rs`:

```rust
FolderAccess::canonical(id: String, path: impl AsRef<Path>, mode: FolderMode)
    -> Result<FolderAccess, AccessError>

AgreementEngine::serve_folder(
    &self,
    id: &str,
    revision: u64,
    peer: ProvenPeer,
    resource: &str,
    sid: u32,
    mux: Arc<Mux>,
    host: Arc<dyn HostServices>,
) -> Result<(), AccessError> // async; owns the entire serving lifetime
```

Canonicalize the actual host-selected folder before generating the offer binding
and signed review. RO is the default. A peer open selects only a resource ID from
the accepted exact bundle; it must not supply a replacement root, mode or peer
identity. Use the existing temporary PAKE/proof/review/acceptance flow, then call
this method with that sealed context and the **same shared per-peer Mux** that
routes subsequent chunks/close frames. Do not fall back to generic standing
mount or shell admission.

The host requires Linux or Windows plus `mount-server`. It pins the
host-selected root before acknowledgement, registers a bounded same-generation
Mux stream, and sends the existing `mount-open-ack { sid, caps }` only after
root/registration/server setup. The existing mount protocol serves requests with
its existing path protections and server-enforced RO/RW decision. No OS mount is
performed.

Linux pins a directory descriptor and serves the existing confined path
protocol. Windows pins the root through the retained `WinRoot` HANDLE: the final
root component is opened with `FILE_OPEN_REPARSE_POINT` and refused if it is a
junction/symlink/reparse point, a following open must report the same volume
serial/file identity, and every request opens each component relative to the
previous directory HANDLE. There is no path join and no unchecked fallback. A
root renamed or substituted after acknowledgement does not redirect the live
share. `ReadLink` is refused because the Windows endpoint does not advertise
symlink support.

Every filesystem request, including requests already buffered on the server,
rechecks the agreement's effective accepted scope under the engine mutex. The
mutex is released before filesystem/network work. A request admitted **before**
revocation may finish; previously copied bytes or completed writes cannot be
rolled back. End/removal blocks subsequent admission, cancels and joins the
owned server task, and closes only that SID generation. Owner-task abortion also
aborts the server and schedules generation-safe Mux cleanup.

Representative errors: `Unsupported` for absent feature/platform pinning;
`Unavailable` for inaccessible root/proc-FD/backend failure; `InvalidSpec` for a
noncanonical or invalid requested resource; `Capacity` for shared-stream limits;
`WrongPeer`, `NotAccepted`, `StaleRevision`, `Expired`, or `Ended` for failed
agreement admission. These are not successful endpoint activations.

## Recipient read/download seam

The existing `mount_proto::MountClient::from_mux_v2(transport, sid, rx, caps)` can
consume the same protocol after a matching authenticated acknowledgement and
validated `parse_mount_caps` result. Register the recipient SID before sending
the open; retain ownership until the client/session ends. Use `path_encode` for
native relative paths, then `MountOp::{GetAttr, Open, Read, Release}`. Bound each
read by negotiated caps and the existing protocol payload limit. Constrain local
download destination creation, filenames, collisions and partial-file publication
using the existing safe receive storage helpers, not peer-provided absolute paths.

`download_output::OwnedDownload` is the owned publisher for that seam. It takes
a caller-selected existing directory and one plain name; peers never supply an
absolute destination. Linux links the pinned open inode into place with
no-clobber `linkat`. Windows creates the staging file relative to the pinned
directory HANDLE and renames that open HANDLE with `replace_if_exists = 0`, so
an existing name is never replaced and concurrent publishers get distinct
`name-1`, `name-2`, ... results. Publication is atomic on one volume. Windows
has no guaranteed directory-entry durability primitive, so a successful
publication reports `durable = false` when the best-effort directory flush is
unavailable; a real flush I/O failure after commit returns
`DurabilityUnknown(path)` rather than success.

Important current client limitations:

- Async `MountClient::call` discards the v2 binary response suffix. It is **not a
  working download implementation**. Existing `call_sync_binary(op, None)` returns
  `(MountResponse, Option<Bytes>)` and preserves the read data; it runs on an
  owned blocking adapter thread, never directly on an async runtime thread. Its
  response wait is bounded at 45 seconds, but the adapter still needs its own
  session cancellation and complete-download integrity/outcome handling.
- Call `set_read_only(true)` for accepted RO access. Do not infer RO solely from
  `max_write_size == 0`: `from_mux_v2` currently treats zero size as unspecified
  and replaces it with a default. The host remains the authoritative RO guard.
- Existing `from_mux` bridge channels are unbounded. A downstream queue cap does
  not make those bridges, or the transport's upstream legacy `Ev` queue, bounded.
  Own/bound the producer and receiver before claiming flood-safe client serving.
- An acknowledgement is a protocol endpoint, not a local folder mount path.
  FUSE/WinFsp readiness must come from actual platform activation; absent setup
  should offer only a genuinely implemented Download action or explicit
  unavailable status. Labels and `.mesh` names are not mounts or DNS readiness.

## Required adapter validation

Use two independently driven authenticated peers over the real CLI/signaling
flow, isolated config roots and actual files. Verify signed mixed-scope review,
explicit acceptance, real RO read/download byte integrity, RW only when offered,
no contact/enrollment persistence, live removal/end closing the folder endpoint,
and no unrelated agreement/SID teardown. Test expiry and changed revision/peer
refusal. Do not replace the echo/read assertions with expected reset or report
that a displayed path is mounted without platform activation.

The core08 and Windows `e121b2ff` host fixtures already cover RO reads and
write/rename rejection, symlink/parent escapes, actual RW write/rename,
pinned-root substitution, buffered requests after revoke, and task-abort cleanup.
They do not replace these recipient/CLI/platform tests.

On `integration/access-shell-cli` the recipient adapter is integrated for the
CLI on both Linux and Windows (`folder_access::perform` + `platform::
folder_download_supported`). Linux runs the real two-process folder E2E. Windows
runs the compiled CLI, recipient protocol/publication tests and the core Windows
suite, but the interactive two-process CLI E2E is not validated: on the leased
runner the interactive `tunlion` process overflowed its stack on ConPTY before
the menu. Treat the Windows CLI folder flow as protocol-tested, not end-to-end.
