#!/bin/sh
# Build vault-core (with its bundled libgit2) for iOS device and simulator.
# T3.5 spike script. Run from the repository root:
#
#   sh core/build-libgit2-ios.sh
#
# Prerequisites: full Xcode with the iPhoneOS + iPhoneSimulator SDKs,
# cmake, and the Rust iOS targets:
#
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#
# Notes:
# - libgit2 is not built separately: the `git2` crate pulls in
#   `libgit2-sys`, which compiles the bundled libgit2 C sources and
#   statically links them into the resulting rlib. There is no dynamic
#   dependency to ship.
# - `IPHONEOS_DEPLOYMENT_TARGET=16.0` matches the v1 minimum
#   (docs/01-overview.md). The newest SDK (e.g. iPhoneOS 18.x) is fine;
#   the deployment target is what sets the minimum OS.
set -eu

export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"

for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    echo "=== $target ==="
    cargo build -p vault-core --target "$target"
done

echo "OK. Artifacts:"
ls -la "target/aarch64-apple-ios/debug/libvault_core.rlib" \
    "target/aarch64-apple-ios-sim/debug/libvault_core.rlib"
