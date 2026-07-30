# secret-write

Write secret data to disk with platform-appropriate restrictive permissions,
atomically. One small, dependency-light helper so every part of a system writes
private keys and tokens the same way.

- **Unix:** the file is created `0600` (owner read/write only).
- **Windows:** the DACL is restricted to the current user (via `icacls`).
- **Atomic:** write to a temp file in the same directory, then rename over the
  target, so a reader never sees a half-written or world-readable intermediate.

Pure `std` (plus `std::process::Command` for the Windows ACL path) — no `windows`
crate, no async runtime, no app coupling. Extracted from
[filament](https://github.com/Abdk4Moura/filament) so its trust crates share one
byte-identical secret writer.

## Usage

```rust
use secret_write::SecretFile;

// Create/overwrite atomically with restrictive permissions.
SecretFile::write("/path/to/id_ed25519", key_bytes)?;
SecretFile::write_str("/path/to/token", "s3cr3t")?;

// Tighten permissions on an existing file.
SecretFile::restrict("/path/to/existing")?;
# Ok::<(), std::io::Error>(())
```

## Status

Pre-1.0; API may change between minor versions. Part of filament.

## License

MIT
