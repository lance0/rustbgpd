# GR EoR stale-resolution attribution inputs

The two JSON lines are the direct bench output behind the
[follow-up receipt](../../gr-eor-stale-resolution-attribution-2026-10.md):
`stale-resolution-dual-sets-1.jsonl` is the uniform control and
`stale-resolution-dual-sets-148667.jsonl` is the synthetic MED-distinct
control. Both used 1,000,000 IPv4 plus 200,000 IPv6 routes, the same
optimized binary, and ordered VPNv4, IPv4 and IPv6 EoRs. One sample of each
ran on 2026-10-02 16:57:55–16:58:11 UTC on core 36. The repository host lock
and a separate benchmark lock were held across both cells. Pre-run checks found no
competing build, profiler, benchmark or daemon process. Host load was
1.60–1.69 with 107 GiB available memory; a shared model scheduler was active.
The local process and host receipts remain outside this compact public artifact.

The source base was `7d088c280d3878b4571012922ff73fce6421fc5b`. The
full four-Rust-file code diff from that base used for the **final** run has
SHA-256 `887f19ecbcbeceea0f277051d0ba1ae4206fc668504b5bb967042bfaf9ad3869`
(`git diff HEAD --binary --` over those four paths). The run driver checked
SHA-256 `2130501e616e670f65dd8cd754640a69df81b92a99f763cb23aa9525d785b10b`
for the then-unstaged sweep-timer addition; the preceding clear-timer edits
were already staged.
The final optimized `gr_end_of_rib` executable SHA-256 was
`104e1f7bab6ce5a23f7dfa61112d0174784972076a68214bd749427ecb7b04b1`.
Rust and Cargo were 1.99.0. The run used `--locked` dependencies and
`bench-internals`; build and run commands are in the receipt. Both source diff
hashes are code-only and predate this documentation. A preceding clear-only
exploratory binary and its rows are separate intermediate evidence; neither
is included in this public final-binary pair.

All rows have `affected=changed=retained_stale=envelopes=0`, complete GR only
after the last family, and report interned set count equal to the requested
count with sufficient capacity. `stale_sweep_ns` brackets the consecutive GR
`sweep_stale_family()` and `sweep_llgr_stale_family()` calls; `clear_stale_ns`
brackets the next GR `clear_stale()` call. The separate post-dispatch stale
check occurs outside `total_ns`. `SHA256SUMS` seals the two raw rows.
