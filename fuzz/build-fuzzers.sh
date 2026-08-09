#!/bin/bash -eu
# Copyright 2026 the rustbgpd authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Heavy-lab classifier receipt: this standalone builder is lab-independent.
# Shared OSS-Fuzz / ClusterFuzzLite build: inventory validation remains on the
# path that produces binaries, rather than being only a separate CI assertion.
repo_root=${1:-"$SRC/rustbgpd"}
: "${OUT:?OUT must name the fuzzer output directory}"

# The upstream base-builder-rust image can trail rustbgpd's workspace MSRV.
# Select the single reviewed nightly shared by both hosted integrations.
RUSTUP_TOOLCHAIN=$(cat "$repo_root/fuzz/rust-nightly.txt")
export RUSTUP_TOOLCHAIN

inventory=$(python3 "$repo_root/scripts/check_fuzz_target_inventory.py" --print-targets)
if [ -z "$inventory" ]; then
  echo "fuzz target inventory returned no targets" >&2
  exit 1
fi

# All six fuzz crates use the same sanitizer, target triple, and build mode.
# Keep one explicit build output layout for both hosted integrations; no
# wall-clock improvement is asserted without a retained benchmark harness.
build_target_dir=${CARGO_FUZZ_TARGET_DIR:-"$repo_root/target/cargo-fuzz"}

for dir in crates/bfd crates/evpn crates/mrt crates/policy crates/rpki crates/wire; do
  pushd "$repo_root/$dir"
  cargo fuzz build -O --debug-assertions --target-dir "$build_target_dir"
  while read -r target_crate name; do
    if [ "$target_crate" != "$dir" ]; then
      continue
    fi
    binary="$build_target_dir/x86_64-unknown-linux-gnu/release/$name"
    if [ ! -x "$binary" ]; then
      echo "expected fuzz target binary is missing: $dir/$binary" >&2
      exit 1
    fi
    cp "$binary" "$OUT/"
    if [ -d "fuzz/seeds/$name" ]; then
      zip -jr "$OUT/${name}_seed_corpus.zip" "fuzz/seeds/$name"
    fi
    if [ -f "fuzz/$name.options" ]; then
      cp "fuzz/$name.options" "$OUT/$name.options"
    fi
  done <<<"$inventory"
  popd
done
