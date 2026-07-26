# Wire-codec allocation artifacts

This directory retains the compact, sanitized evidence behind
[`../../wire-codec-allocation-2026-07.md`](../../wire-codec-allocation-2026-07.md).

## Browsable files

- `aggregate.csv`: the four six-pair Criterion comparison summaries.
- `attempts.csv`: all 24 paired attempts with unrounded Criterion median
  estimates and derived head-versus-base deltas.
- `allocations.csv`: both diagnostic rows from all eight H/S/P and repeat
  runs, including exact request kinds, requested bytes, and fixture digests.
- `commands.txt`: comparison, diagnostic, red-proof, and verification
  commands with local paths replaced by placeholders.
- `provenance.txt`: source identities, toolchain, CPU, kernel, governor, lock
  digest, and measured-binary digests.
- `red-proofs.md`: the five source mutations, the 9,999-operation harness
  mutation, and the allocation positive/negative controls.
- `raw-selected-manifest.csv`: hashes and sizes for the 182 selected raw
  campaign inputs, addressed only by normalized archive member name.
- `sanitized-manifest.csv`: hashes and sizes for all 183 public evidence
  payloads after deterministic sanitization and addition of `red-proofs.md`.
- `wire-codec-allocation-evidence.tar.gz`: the deterministic sanitized
  archive.
- `verification.txt`: retained archive reproduction, safety, count, hash, and
  privacy scan results.
- `SHA256SUMS`: hashes for every sibling artifact except itself.

The archive has one top-level directory,
`lan622-wire-codec-evidence/`. It contains exactly 184 regular files: 183
evidence payloads plus their internal `SANITIZED_SHA256SUMS` manifest. The
payloads are 48
timing logs, 48 `estimates.json` files, 48 `sample.json` files, four each of
timing metadata, summaries, and binary validations, eight each of allocation
JSONL, metadata, and stderr logs, one completion marker, one allocation-gate
receipt, and one combined red-proof receipt.

## Selection and sanitization

The source campaign occupied 3,472,447,161 bytes across 12,721 files. The
archive selects 262,737 bytes across 182 raw files before sanitization. It
excludes Cargo target directories, detached worktrees, compiled binaries,
Criterion `new`, `report`, `benchmark.json`, and `tukey.json` files, duplicated
driver/campaign logs, the empty host-lock file, and the source campaign's
all-files checksum list.

Absolute campaign, worktree, target, source, and binary paths are replaced with
`<RUN_ROOT>`-relative logical paths. The machine hostname is replaced with
`<BENCH_HOST>`. No username, home path, temporary absolute path, AI/tool
attribution, symlink, hard link, device, or traversal member is retained.
`raw-selected-manifest.csv` binds the selected pre-sanitization bytes without
publishing their source paths; `sanitized-manifest.csv` binds the public
archive bytes.

## Integrity and safety

Verify the browsable artifacts:

```console
sha256sum -c SHA256SUMS
```

Verify the archive without extracting it:

```console
gzip -cd wire-codec-allocation-evidence.tar.gz |
  tar -tf - >/dev/null
```

After extracting to an empty directory, verify the internal public manifest:

```console
tar -xzf wire-codec-allocation-evidence.tar.gz
cd lan622-wire-codec-evidence
sha256sum -c SANITIZED_SHA256SUMS
```

The tarball was produced twice from the same sanitized stage with sorted member
names, numeric owner/group 0, normalized 0755 directory / 0644 file modes,
mtime 0, and gzip's name/timestamp fields disabled. Both copies had the same
SHA-256 digest. See `verification.txt` for the retained result and
`commands.txt` for the exact deterministic recipe.
