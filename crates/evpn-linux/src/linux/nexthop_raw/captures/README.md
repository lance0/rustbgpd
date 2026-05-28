# Reference captures — `ip nexthop` wire-format strace decode

The four `.log` files in this directory are the strace decodes of
iproute2's `ip nexthop add` / `ip nexthop del` invocations under an
unprivileged user namespace, used as the structural reference for
the byte-fixture tests in `../encode.rs`.

These are **reference material only** — not part of the build, not
checked by any test. They exist so a future reader can verify that
the expected-bytes constants in `encode.rs` were derived from a
real iproute2 run, not invented from the UAPI spec alone.

## Environment

- iproute2 version: 6.1.0 (dev box, 2026-05-12)
- libbpf: 1.3.0
- Kernel: 6.17.0-20-generic
- Capture command:
  ```bash
  sudo unshare -rn bash -c '
    strace -e trace=sendmsg -x -s 4096 -o /tmp/nh-cap1.log ip nexthop add id 12 via 10.0.0.2 fdb
    strace -e trace=sendmsg -x -s 4096 -o /tmp/nh-cap2.log ip nexthop add id 13 via 10.0.0.3 fdb
    strace -e trace=sendmsg -x -s 4096 -o /tmp/nh-cap3.log ip nexthop add id 200 group 12/13 fdb
    strace -e trace=sendmsg -x -s 4096 -o /tmp/nh-cap4.log ip nexthop del id 200
  '
  ```

## Files

| File | Command | Structural shape |
|---|---|---|
| `nh-cap1.log` | `ip nexthop add id 12 via 10.0.0.2 fdb` | `RTM_NEWNEXTHOP` + `nh_family=AF_INET` + `[NHA_ID(12), NHA_GATEWAY(10.0.0.2), NHA_FDB]` |
| `nh-cap2.log` | `ip nexthop add id 13 via 10.0.0.3 fdb` | Same as cap1 with id=13, gw=10.0.0.3 |
| `nh-cap3.log` | `ip nexthop add id 200 group 12/13 fdb` | `RTM_NEWNEXTHOP` + `nh_family=AF_UNSPEC` + `[NHA_ID(200), NHA_GROUP([{12,0},{13,0}]), NHA_FDB]` |
| `nh-cap4.log` | `ip nexthop del id 200` | `RTM_DELNEXTHOP` + `nh_family=AF_UNSPEC` + `[NHA_ID(200)]` |

## Differences vs our encoder

| Field | iproute2 (these captures) | `encode.rs` |
|---|---|---|
| `nlmsg_flags` (add) | `REQUEST \| ACK \| EXCL \| CREATE` | `REQUEST \| ACK \| CREATE \| REPLACE` |
| Why | one-shot CLI semantics (fail if exists) | idempotent reconcile semantics; ADR-0059 §5 invariant 3 requires REPLACE for atomic alias-set update |

All other fields (attribute order, attribute lengths, `nh_family`,
`nlmsg_type`, struct sizes) match byte-for-byte.

## Regenerating

Bump the iproute2 version string above and re-run the capture
command. If iproute2's wire format diverges from these captures in
a structurally meaningful way (e.g., new attribute, different
order), the encoder + tests need to be updated to match.
