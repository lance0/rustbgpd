# Released v0.75.0 runtime-state samples

These files were emitted by the official Linux amd64 v0.75.0 daemon, then
copied unchanged out of its runtime directories. This is a named-release reader
regression sample, not a supported-minor window or an upgrade/downgrade promise.
It covers the formats the [v0.74.0 sample](../v0.74.0/README.md) left out.

- `fib-owned.json`: general FIB ownership receipt (envelope version 5) with two
  installed IPv4 routes in table `fixture`.
- `blackhole-owned.json`: BLACKHOLE ownership receipt
  (`rustbgpd.blackhole-owned/v1`) for one discard route.
- `commit-confirm/`: the v3 pending authority of one confirmed apply, taken
  while it was pending: the config-adjacent locator (published as
  `config.toml.commit-confirm-locator.json`), the metadata, and the raw
  normalized prior config.
- `events.db`: the event-history store (`metadata.schema_version = 1`) after
  coordinated shutdown.
- `warm-bundle-v1/`: the shutdown warm checkpoint (manifest `format_version = 2`
  and its MRT snapshot) for one Established IPv4 view with no routes.
- `gr-restart.toml`: the v3 restart marker written with that checkpoint; its
  `checkpoint_generation` names the bundle.
- `capture.json` and `daemon.log`: binary/archive identities, steps, isolated
  container image and exit status. The log concatenates the subject daemon's
  stdout and stderr, trimming only trailing whitespace.
- `config.toml` and `peer.toml`: the subject and peer inputs, not
  daemon-written artifacts.

## Capture

Two containers on an internal Docker network (`192.0.2.0/29`, no external
connectivity) run the same release binary: the subject at `192.0.2.2` and an
eBGP peer at `192.0.2.3`. The subject runs as container root with only
`CAP_NET_ADMIN` (kernel route installs in its own network namespace) and
`CAP_NET_BIND_SERVICE`. In order, the script:

1. has the peer inject `198.51.100.0/24` and BLACKHOLE `203.0.113.1/32`, then
   copies both ownership receipts once the subject installed the routes;
2. plans and applies a confirmed change of the neighbor description, copies
   the pending authority, then confirms it;
3. has the peer withdraw both routes and waits for empty receipts;
4. stops the subject with SIGTERM and copies the marker, event store and bundle.

v0.75.0 cannot publish a warm checkpoint that holds an IPv4 unicast route
learned over BGP: the stored route keeps its `NEXT_HOP` attribute, the MRT
encoder adds another, and the recovery check rejects the duplicate. Step 3
exists so the checkpoint is published at all; the bundle therefore has no
routes.

## Reproduce

Download `rustbgpd-linux-amd64.tar.gz` and `checksums-linux-amd64.txt` from the
[v0.75.0 release](https://github.com/lance0/rustbgpd/releases/tag/v0.75.0).
The capture script pins the verified archive, daemon and CLI SHA-256 values.
From the repository root, with Python 3.11+, Docker, a locally available
`debian:trixie-slim` image and `192.0.2.0/29` unused by other Docker networks:

```sh
python3 scripts/capture-released-state-v075.py rustbgpd-linux-amd64.tar.gz /tmp/released-state-capture
cargo test --locked -p rustbgpd --bin rustbgpd released_v075
cargo test --locked -p rustbgpd-event-history -p rustbgpd-mrt --lib released_v075
```

Use a new output directory. The script compares the recapture with these
samples: both ownership receipts, the locator and the raw prior must match
byte for byte; the metadata and manifest must match apart from the deadline,
raw-file device/inode, checkpoint generation, timestamps and snapshot name;
the event store must have the same schema version and `sqlite_master`. It
retains both daemon logs, removes its containers and network, and preserves
the original failure if cleanup fails.

As in v0.74.0, these artifacts were never files in the release's Git tree, so
`git show` cannot authenticate them. Their provenance is the verified release
binary, this capture receipt and the reproducible writer exercise.

## Reader coverage

Tests copy the archived bytes into owner-private temporary directories and
never modify the originals. Each accepts the released instance through the
current reader and refuses a copy declaring the next version:

| Artifact | Accepted | Next version |
|----------|----------|--------------|
| FIB receipt | Both routes adopted under the archived `[[fib_tables]]` entry | Version 6 is quarantined to `.stale`; nothing owned |
| BLACKHOLE receipt | Prefix adopted, kernel mutations available | `/v2` schema disables mutations; file untouched |
| Commit-confirm v3 | Locator and metadata decode, linkage, raw digest and retained-snapshot checks pass | Version 4 locator and metadata refused |
| Event store | Opens in place; allocator continues at 28 | Schema 2 refused in place, not quarantined |
| Warm bundle | Startup scavenging keeps it; full load and snapshot decode pass | Format 3 refused by both; files untouched |
| GR marker | v3 decodes with the bundle's generation | Version 4 refused |

The commit-confirm metadata binds the capture host's raw-file device and inode,
so boot recovery cannot be replayed from these files; the test supplies the
recorded identity to the raw check instead. No runtime-state artifact is added
to the v1 stable-surface inventory, and this sample does not create a
next-release freeze gate.
