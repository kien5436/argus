# Core build notes

## iOS: libgit2 spike (T3.5)

`vault-core` uses the `git2` crate, which pulls in `libgit2-sys`. That
crate compiles the bundled libgit2 C sources at build time and links
them statically into `libvault_core.rlib`. There is no separate libgit2
to build, no dynamic library to ship, and no extra signing step.

### Reproduce

Prerequisites: full Xcode (iPhoneOS + iPhoneSimulator SDKs), cmake, and
the Rust targets (`rustup target add aarch64-apple-ios
aarch64-apple-ios-sim`). Then from the repo root:

```sh
sh core/build-libgit2-ios.sh
```

This builds `vault-core` for `aarch64-apple-ios` (device) and
`aarch64-apple-ios-sim` (simulator) with
`IPHONEOS_DEPLOYMENT_TARGET=16.0` (the v1 minimum). Any recent SDK
(e.g. iPhoneOS 18.x) works; the deployment target sets the minimum OS.

### Result (2026-11-24, Xcode 16.2, iPhoneOS 18.2 SDK, Apple M-series)

- `cargo build -p vault-core --target aarch64-apple-ios`: OK (~7 s warm).
- `cargo build -p vault-core --target aarch64-apple-ios-sim`: OK (~7 s warm).
- `libvault_core.rlib`: ~7.9 MB per target (debug).

### Simulator smoke runs (T3.5-02, T3.5-03)

Test binaries built with
`cargo test -p vault-core --target aarch64-apple-ios-sim --no-run`
were executed in a booted simulator via
`xcrun simctl spawn booted <test-binary>`:

- T3.1-05 (libgit2 backend, all local cases: init, commit, history):
  passes in the simulator.
- `remote` suite (T3.2, incl. the local-HTTP-server HTTPS test): 9/9
  pass in the simulator.
- `net_retry` suite (T3.4): 5/5 pass in the simulator.
- A throwaway libgit2-only init/commit check (since removed) passed
  in the simulator.

### Spike finding: `SystemBackend` cannot run on iOS

Tests that shell out to the system `git` binary fail in the simulator
(`git not found` / sandbox `NotFound`): there is no `git` executable in
the iOS sandbox. On iOS only `Libgit2Backend` is viable, and backend
selection there must resolve to libgit2 unconditionally. This is
consistent with the current `select_backend_for_path` design (empty
`PATH` yields libgit2) and needs no code change yet; the T9.x Swift
harness must use `Libgit2Backend` directly.
