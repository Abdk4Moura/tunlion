# Browser transfer-policy wasm

The browser's transfer allow/deny decision is the shared Rust policy in
`crates/filament-policy`, compiled to WebAssembly by
`crates/tunlion-policy-wasm`. This directory is where the generated module is
committed, exactly like `frontend/src/pake/` holds the shared PAKE module.

## Files (generated, committed)

```text
tunlion_policy_wasm.js            wasm-bindgen glue (target web)
tunlion_policy_wasm_bg.wasm       the compiled policy
tunlion_policy_wasm.d.ts          exported types
tunlion_policy_wasm_bg.wasm.d.ts  wasm exports
```

Do not hand-write or edit these files. They are build output.

## Rebuild

```sh
bash crates/tunlion-policy-wasm/build-wasm.sh
```

Requires Rust 1.88.0, the `wasm32-unknown-unknown` target, and
`wasm-bindgen-cli` 0.2.122 (the wasm-bindgen version pinned in `Cargo.lock`).

CI produces the same files in `.github/workflows/policy-wasm.yml` and fails if
they differ from what is committed. To update them:

1. Run the **Browser policy wasm** workflow (push, PR, or manual dispatch).
2. Download its `policy-wasm` artifact.
3. Commit the four files over this directory.

Nothing was generated locally in the change that introduced this directory; the
first workflow run is what produces the artifact. Until it is committed, the
frontend still builds: `frontend/src/lib/policyCore.js` resolves no module, and
`frontend/src/lib/policy.js` returns an `unsupported` denial, so offers wait for
a click instead of being auto-accepted. The `policy-wire` browser gate fails
loudly in that state rather than skipping.

## Consumer

`frontend/src/lib/policy.js` translates browser facts into the JSON input,
calls `admitTransfer(JSON)` with an explicit `now`, and maps the core's answer
to allow/deny. It contains no allow rule.
