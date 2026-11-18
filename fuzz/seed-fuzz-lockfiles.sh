#!/bin/bash -eu
# Seed every fuzz workspace's lockfile from the reviewed workspace lockfile.
#
# Each crates/*/fuzz crate is its own workspace with no tracked lockfile, so a
# bare build resolves every dependency to its newest release, and one that
# needs a newer std than the pinned nightly breaks fuzzing with no change in
# this repository. Cargo keeps the seeded versions and drops unused entries,
# so only fuzz-only crates such as libfuzzer-sys resolve fresh. Every path
# that builds fuzz targets runs this first; scripts/check_fuzz_toolchain_pin.py
# enforces that.
repo_root=$(cd "$(dirname "$0")/.." && pwd)
for dir in "$repo_root"/crates/*/fuzz; do
  cp "$repo_root/Cargo.lock" "$dir/Cargo.lock"
done
