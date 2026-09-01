# filament-transfer

Out-of-order chunk reassembly and short-write-safe positional writes, with no
opinion about how a peer was found, authenticated, or displayed.

Carved out of the [filament](https://github.com/Abdk4Moura/filament) CLI so the
mechanics are usable on their own. Zero dependencies beyond `std`.

```rust
use filament_transfer::{record_range, coverage_complete, first_gap};

let mut ranges = Vec::new();
record_range(&mut ranges, 10, 10);          // a chunk arrives out of order
record_range(&mut ranges, 0, 5);
assert!(!coverage_complete(&ranges, 20));
assert_eq!(first_gap(&ranges, 20), Some(5)); // resume here
```

`record_range` returns `(newly covered, total covered)`. The first value is what
progress should advance by: counting the raw chunk length instead double-counts
a resend and reports a file complete before it is.

`pwrite_at` loops until the whole buffer lands. A positional write may write
fewer bytes than asked, and discarding that count leaves a hole in the file while
the progress counter advances by the full length: silent corruption, measured at
~44% on direct QUIC and ~88% on a WebRTC data channel for large files before it
was fixed. It returns the iteration count so the CALLER can report a short write;
printing from inside a write primitive is what it used to do, and that is the
coupling this crate exists to avoid.

`safe_incoming_name` reduces a remote-supplied filename to a single safe path
component: basename only, no separators, no control bytes.

MIT licensed.
