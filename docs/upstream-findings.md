# Upstream findings (GoBGP, pmacct, SR Linux)

Behaviors found in peer/collector/NOS software during rustbgpd interop lab
development, recorded so they can be reported/patched upstream. Each entry lists the observed behavior,
a reproduction sketch, the workaround the interop fixtures use, and a severity
read. Versions are the ones the labs ran; re-verify against GoBGP master
before filing.

Context: the M-series interop labs pair rustbgpd (RR role) with GoBGP peers
under containerlab. These findings surfaced while validating rustbgpd's
RT-Constrain, GR/LLGR, and labeled-unicast arcs. Two-way honesty: the same
labs also caught real rustbgpd bugs via GoBGP's strictness — that history
lives in `CHANGELOG.md` and the milestone docs, not here.

---

## 1. Segfault on `vrf del` while a default RTC NLRI is in the table

- **Version:** 3.37.0 (observed during M75 development)
- **Behavior:** with a default (zero-length) RT-Constrain NLRI present in the
  RTC table, `gobgp vrf del <name>` crashes the daemon (nil-pointer style
  segfault) instead of removing the VRF.
- **Repro sketch:** peer negotiates AFI 1 / SAFI 132; the peer originates a
  default RTC NLRI (RFC 4684 §4 zero-length membership); create any VRF with
  an RT; `gobgp vrf del <name>`.
- **Workaround:** the M75 fixtures avoid `vrf` lifecycle entirely and manage
  RTC membership via `gobgp global rib add/del -a rtc` instead.
- **Severity:** crash — highest-value report of the set. Likely fixed or
  moved in 4.x; re-test on master first.

## 2. RTC withdraw processing ignores a still-covering default RTC NLRI

- **Version:** 4.6.0 (observed during M77 development)
- **Behavior:** when a specific RTC membership route is withdrawn, GoBGP's
  RTC-membership withdraw path prunes the VPN routes that matched it without
  first checking whether a *broader, still-present* RTC NLRI (e.g. the
  zero-length default) also covers them. RFC 4684 matching is
  longest-covering-prefix over the 96-bit origin-AS+RT space: routes covered
  by a remaining default should keep flowing.
- **Repro sketch:** peer A holds both a default RTC NLRI and a specific
  RT membership toward GoBGP; VPN routes matching that RT are advertised to A;
  withdraw only the specific RTC route while the default remains → GoBGP
  withdraws the VPN routes from A even though the default still covers them.
- **Workaround:** the M77/M78 topologies give the affected peer
  config-derived, origin-symmetric membership so the pruned-too-early path
  is never exercised.
- **Severity:** correctness — silent VPN route loss in RTC deployments that
  use default membership as a safety net.

## 3. Label-only change to an existing labeled path is never sent on the wire

- **Version:** 4.6.0 (observed during M79 development)
- **Behavior:** re-adding an `ipv4-labeled-unicast` path that differs from
  the current one **only in the MPLS label** does not generate an UPDATE
  toward peers. GoBGP's own table and adj-out views show the new label, but
  the peer's `updates_received` counter stays flat and the peer keeps the
  old label. Path-attribute changes (e.g. a community) do trigger the UPDATE.
  Likely an implicit-withdraw/identity comparison that excludes the label
  from "did this path change" for labeled families — even though for
  SAFI 4/128 the label is forwarding-critical data.
- **Repro sketch:** `gobgp global rib add -a ipv4-labeled P L1 nexthop N`;
  wait for propagation; `gobgp global rib add -a ipv4-labeled P L2 nexthop N`
  → peer never learns L2.
- **Workaround:** the M79 relabel test carries a community change alongside
  the new label to force the UPDATE onto the wire.
- **Severity:** correctness — a relabel that never propagates means traffic
  black-holes at the old label in a real MPLS control plane.

## 4. Labeled withdraws echo the original label stack instead of the RFC 8277 §2.4 compatibility field

- **Version:** 4.6.0 (observed during M79 development)
- **Behavior:** GoBGP encodes MP_UNREACH_NLRI for labeled families by
  echoing the route's original label stack. RFC 8277 §2.4 says the label
  field in withdraws SHOULD be set to the 0x800000 compatibility value (one
  3-octet entry) and MUST be ignored on receipt. Stack-echo is arguably
  within the letter of the SHOULD, but it is an interop hazard: a receiver
  that parses withdraws as "one 3-octet field + prefix" mis-computes the
  prefix length on any multi-label withdraw. (rustbgpd had exactly that
  strictness and hard-reset the session — fixed on our side to accept both
  forms; strict receivers elsewhere will hit the same wall.)
- **Related:** GoBGP also announces multi-label stacks without negotiating
  the RFC 8277 §2.1 Multiple Labels capability, which is what makes the
  stack-echo withdraw reachable against peers that never advertised
  multi-label support.
- **Repro sketch:** announce `ipv4-labeled` with stack `L1/L2`; withdraw it;
  capture MP_UNREACH — the NLRI carries both label entries rather than
  0x800000.
- **Workaround:** none needed post-fix on the rustbgpd side (we accept the
  0x800000 form and the stack-echo form); worth an upstream discussion on
  emitting the compliant compatibility field, or gating multi-label on the
  capability.
- **Severity:** interop hardening — low urgency for GoBGP↔GoBGP, real
  against strict third-party receivers.

---

# Upstream findings (pmacct)

Found while validating the M81 BMP trio receipt against
`pmacct/pmbmpd:bleeding-edge` (1.8.1-git 20260513, commit `cd619f58`).

## 5. BMPv4 RM TLV code points are pre-tlv-20 while the source claims tlv-20

- **Version:** pmbmpd 1.8.1-git 20260513 (bleeding-edge)
- **Behavior:** `src/bmp/bmp.h` defines the Route Monitoring TLV code
  points as `SP=1, GROUP=2, VRF=3, BGP_PDU=4, MARKING=5` under a comment
  claiming "provisional code points: draft-ietf-grow-bmp-tlv-20" — but
  tlv-20 §9 assigns `Group=4, VRF/Table Name=5, Stateless Parsing=6,
  BGP Message=7`. A tlv-20-conformant sender's Route Monitoring messages
  (UPDATE in BGP Message TLV type 7) are all discarded with
  `[route monitor] packet discarded: BMPv4 BGP PDU TLV != 1` (verified
  live: pmbmpd parses the indexed TLV structure fine — `bmp_tlv_list_add():
  type=7 len=… tlv_idx=0` — then finds no TLV of its expected type 4).
  Stats Reports are also read in the RFC 7854 layout with no tlv-20
  Stats TLV (code 1) container, so a v4 Stats Report's first TLV header
  bytes would be misread as the Stats Count.
- **Workaround:** the M81 fixtures use pmacct as a v3-only semantic
  oracle; BMPv4 framing is asserted byte-level and via tshark's generic
  TLV-header dissection.
- **Severity:** interop — any tlv-20 v4 sender loses its entire RM
  stream silently (Initiation/PeerUp/PeerDown still decode, since those
  differ from v3 only in the version byte).

## 6. Indexed-TLV index field read as one byte

- **Version:** pmbmpd 1.8.1-git 20260513 (bleeding-edge)
- **Behavior:** `bmp_tlv_hdr_get_index()` in `src/bmp/bmp_msg.c` does
  `(*idx) = ntohs((u_int16_t) *idx_ptr)` — dereferencing a `char*` reads
  only the first byte of the 2-byte index (and byte-swaps it), so any
  index > 0 decodes wrong: index 0x0001 reads as 0x0000 ("applies to all
  NLRIs"), and G-bit group indexes collapse. Only index 0 round-trips.
- **Workaround:** none needed for rustbgpd (it currently emits index 0
  only); disqualifies pmacct master as an oracle for per-NLRI/per-group
  TLV attribution.
- **Severity:** correctness — silent TLV misattribution for multi-NLRI
  v4 Route Monitoring messages.

## 7. SR Linux sr_cli batch input silently swallows everything after an unbalanced quote

- **Version:** Nokia SR Linux 25.10.1-399 (observed during M82 development)
- **Behavior:** feeding a CLI config file to `sr_cli --candidate-mode
  --commit-at-end` over stdin, a `#` comment line containing an
  unbalanced quote character (e.g. an apostrophe in prose) opens a
  quoted string that consumes every subsequent LINE of the batch. No
  error is raised: the CLI exits 0, prints nothing, and
  `--commit-at-end` commits the truncated prefix of the config — a
  silently half-configured box.
- **Workaround:** keep sr_cli batch files free of apostrophes/quotes in
  comments (`tests/interop/configs/srl-m82-bundle.cli` carries the
  warning in-line).
- **Severity:** operational — a comment typo turns into a silent
  partial commit with exit code 0.

---

*Last updated alongside the M82 SR Linux VLAN-aware-bundle interop
work. See `tests/interop/` fixture comments for the in-place
documentation of each workaround.*
