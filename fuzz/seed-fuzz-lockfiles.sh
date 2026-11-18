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
#
# Each lockfile is replaced by a rename, so a fuzz build running concurrently
# never reads a truncated file.
repo_root=$(cd "$(dirname "$0")/.." && pwd)
tmp=
trap 'rm -f "$tmp"' EXIT
for dir in "$repo_root"/crates/*/fuzz; do
  if cmp -s "$repo_root/Cargo.lock" "$dir/Cargo.lock"; then
    continue
  fi
  tmp=$(mktemp "$dir/.Cargo.lock.XXXXXX")
  cp "$repo_root/Cargo.lock" "$tmp"
  chmod 644 "$tmp"
  mv -f "$tmp" "$dir/Cargo.lock"
  tmp=
done
