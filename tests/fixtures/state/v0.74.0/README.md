# Released v0.74.0 runtime-state samples

These files were emitted by the official Linux amd64 v0.74.0 daemon, then
copied unchanged from its runtime directory. This is a named-release reader
regression sample, not a supported-minor window or an upgrade/downgrade promise.

- `config-history/v2-*.json`: boot snapshot, including the exact normalized TOML
  and its source manifest and digests.
- `config-history/v3-*.json`: metadata-only snapshot after a successful SIGHUP
  changed the neighbor description to 10 MiB + 1 bytes. The oversized input is
  generated temporarily by the capture script and is not archived.
- `gr-restart.toml`: generationless v3 marker from coordinated SIGTERM shutdown.
- `capture.json` and `daemon.log`: binary/archive identities, invocation, isolated
  container image, acknowledged reload and shutdown, and exit status. The log
  concatenates captured daemon stdout and stderr (including the startup banner),
  trimming only trailing whitespace; state artifact bytes are unchanged.
- `config.toml`: the small starting input, not a daemon-written artifact.

The capture uses one unconnected GR-enabled neighbor in a `--network none`
container. `/etc/rustbgpd/config.toml` and `/var/lib/rustbgpd` are the paths
visible to the daemon. No warm checkpoint is enabled and no BGP session reaches
Established. The marker's boot ID, namespace identity and deadlines are the
actual capture values; they have not been made portable by editing them.

## Reproduce

Download `rustbgpd-linux-amd64.tar.gz` and `checksums-linux-amd64.txt` from the
[v0.74.0 release](https://github.com/lance0/rustbgpd/releases/tag/v0.74.0).
The capture script pins the verified archive and daemon SHA-256 values.
From the repository root, with Python 3.11+, Docker, and a locally available
`debian:trixie-slim` image:

```sh
python3 scripts/capture-released-state.py rustbgpd-linux-amd64.tar.gz /tmp/released-state-capture
cargo test --locked -p rustbgpd --bin rustbgpd released_v074
```

Use a new output directory. The script waits for the boot history row and gRPC
socket before SIGHUP, and for the metadata row before SIGTERM. It checks exit
status and format semantics, and compares recaptured history content against
these samples with only the capture timestamp excluded. It preserves emitted
bytes and logs separately and attempts cleanup on failure. Recovery after a
creation timeout requires the exact container name, owner nonce and image.
`--image` can select an available Linux image; `capture.json` records the image
ID actually used. The original image ID is recorded in this directory.

The runtime artifacts did not exist as files in the release's Git tree, so
`git show` cannot authenticate their bytes. Their provenance is the verified
release binary plus this capture receipt and reproducible writer exercise.
Recapture cannot reproduce wall timestamps, boot IDs, namespace IDs or absolute
boottime deadlines byte-for-byte. This slice does not implement a complete
release-tag byte checker for every runtime-state artifact.

## Reader coverage and remaining scope

Tests copy the archived bytes into owner-private temporary directories. History
v2 must return the exact payload and verified digests despite its retained date;
v3 must remain listed but refuse rollback. A temporary v4 copy retains its
sequence and roster slot as unreadable and blocks new recording. The original
fixtures are never modified by these tests.

The GR test passes the original bytes through `GrRestartMarkerStore::read`, then
uses the existing clock seam to check bounded remaining time and expiry. An aged
marker still causes cold startup; decoding the format does not restore freshness.
A temporary v4 marker must be refused.

FIB ownership, BLACKHOLE receipts, event-store schema, commit-confirm metadata
(which binds to file/path identity), and warm-bundle manifests remain outside
this slice. A warm-bundle capture needs an Established session with negotiated
GR. No runtime-state artifact is added to the v1 stable-surface inventory, and
this sample does not create a next-release freeze gate.
