# Dual-stack route-server policy reload — 2026-09

> **Document class: IN PROGRESS.** The harness extension and the 20-member
> correctness rung are done and published below. The 200-member
> scale-validation rung and the 700-member receipt rung have **not** been
> run; their exact commands are pinned at the end so the receipt rung can
> run as one command in a quiet window. Nothing in this document is a
> 700-member result yet.

Does a policy generation change reach every member's **IPv4 and IPv6**
inventories, completely and independently per family, while operator
queries keep answering? The existing 700 × 400,400 IXP matrix
([`ixp-matrix-2026-07.md`](ixp-matrix-2026-07.md)) is IPv4-only, and
its harness hard-coded an IPv4-unicast OPEN and IPv4 body NLRI, so there
was no dual-stack switch to rerun. This receipt adds that switch and
proves it does not lie.

## The shape, in one line

**700 dual-stack member sessions, 400,400 total unique routes: 200,200
IPv4 /24 plus 200,200 IPv6 /48 (286 + 286 per member).** Not 400,400 per
family. Not comparable with the IPv4-only headline. The full pinned
definition — distribution, overlap, cohorts, policy shapes, churn and
reload schedule, acceptance, instruments, host discipline — was committed
before the first cell and lives in
[`artifacts/ixp-dualstack-2026-09/README.md`](artifacts/ixp-dualstack-2026-09/README.md).

## What the harness now proves (and refuses to fake)

`bench/scale/reloadstall` with `RELOADSTALL_DUALSTACK=1`:

- every stub negotiates IPv4 unicast **and** IPv6 unicast on one session;
  a peer OPEN that omits either family is a fatal establishment error
  ("did not negotiate Ipv6/Unicast (empty family)"), never a session that
  silently counts;
- IPv6 routes are announced and withdrawn through the wire crate's
  `MP_REACH_NLRI` / `MP_UNREACH_NLRI` encoders and decoded the same way at
  every observer;
- every observer keeps an **independent** unique-prefix bitmap per family;
  convergence, reload completion, and the post-completion stable-marker
  proof each require both families at every observer, and an observer's
  completion is its slower family's completion.

`RELOADSTALL_FILTER_COUNT=K` (paired with the generator's
`GEN_FILTER_COUNT=K`) adds the filtering policy shape: generation B
rejects the named base indexes `0..K` of each family; completion of that
reload also needs a withdrawal of every named prefix at every changed
observer, while a named prefix delivered with the marker
(`filtered_leaked`), a withdrawal of any other base prefix at a changed
observer (`bystander_withdrawn`), or any base withdrawal at a stable
observer (`stable_withdrawn`) fails the reload.

### Negative cases

Each of these is a unit test in `bench/scale/reloadstall/src/main.rs`
that fails the completion check, so a packet total cannot masquerade as
delivery:

| Case | Test | What is proven |
|---|---|---|
| Empty family (bitmap) | `dualstack_completion_is_independent_per_family` | Every IPv4 prefix delivered twice over leaves the IPv6 bitmap at 0 and the observer incomplete |
| Empty family (wire) | `dualstack_establishment_fails_closed_on_an_unnegotiated_family` | A peer OPEN carrying only IPv4 unicast fails establishment fatally in dual-stack mode; one carrying both establishes |
| Missing prefix | `dualstack_completion_is_independent_per_family` | Five of six IPv6 prefixes is not completion |
| Duplicate prefix | same, plus `generation_progress_counts_unique_prefixes_only` | Ten repeats of a delivered prefix never fill the missing one |
| Own-slice / out-of-range / wrong family | `base_prefix6_index_round_trips_and_rejects_non_base_routes`, `dualstack_announce_and_withdraw_round_trip_through_mp_attributes` | Own announcements, churn space, wrong prefix length, foreign first segment, and IPv4 body NLRI never advance the IPv6 bitmap |
| Filter leak / bystander / duplicate withdrawal | `filtering_generation_requires_named_withdrawals_and_rejects_leaks` | Bystanders with the marker but no named withdrawals is incomplete; a named prefix with the marker is a leak; a non-named withdrawal is bystander damage; a repeated named withdrawal is counted, not credited |

The wire-level empty-family case was also run end to end at 20 members
(`negative-20-v4only` below): a daemon configured with `ipv4_unicast`
only against dual-stack stubs.

## Rung 1 — 20 members (correctness rung)

20 sessions × (286 IPv4 + 286 IPv6) = **11,440 total, 5,720 per
family**; 16 changed / 4 stable; 4 reloads (B, A, B, A); 30 s control
window; live churn in both families throughout. Measured on a **busy
host** (other builds running, `powersave` governor): this rung validates
behavior, and its timings are context only.

Daemon: rustbgpd built from the source tree of `fe1762118` (the measured
tree adds only bench and docs changes on top; exact identities in each
cell's `provenance.txt`).

| Cell | Result | Sessions / decode errors | Per-family completion (16 changed observers, 4 reloads) | Withdrawal accounting | Operator queries |
|---|---|---|---|---|---|
| `rung1-20-P` (permit-set-preserving) | **pass** | 20/20 / 0 | IPv4 p50 0.02 s, max 0.06 s; IPv6 p50 0.02 s, max 0.06 s | named 0/0 both families; leaked 0, bystander 0, stable 0 | 1,843 `rbgp health` (max 71 ms) and 840 `rbgp rib --prefix` over `20.0.0.0/24` and `3001::/48` (max 51 ms), all exit 0 |
| `rung1-20-F` (filtering, 64 named prefixes per family) | **pass** | 20/20 / 0 | IPv4 p50 0.03 s, max 0.07 s; IPv6 p50 0.03 s, max 0.07 s | named **960/960 per family** on both B reloads (15 observers × 64), 0/0 on both A reloads; leaked 0, bystander 0, stable 0, duplicate 0 | 1,844 `rbgp health` (max 22 ms) and 842 `rbgp rib --prefix` (max 19 ms), all exit 0 |
| `negative-20-v4only` (empty family: daemon `ipv4_unicast` only) | **fails closed, rc 1** | 0 sessions established | — | — | — |

The negative cell's whole harness output is the header and
`stub 0 failed: peer OPEN did not negotiate Ipv6/Unicast (empty family)`:
no session, no convergence, no reload row could exist for a family the
daemon never negotiated. Daemon `VmHWM` was 48 MiB (P) and 85 MiB (F).

Both families converged on their exact bitmaps at every observer
(`first_exact_bitmap` and `first_exact_bitmap6`: 20/20 complete,
`min_unique = max_unique = 5434`) in 0.3 s; stable markers were fresh in
both families at all 4 stable observers after every reload; daemon
`VmHWM` 48 MiB.

Raw artifacts: [`artifacts/ixp-dualstack-2026-09/`](artifacts/ixp-dualstack-2026-09/README.md).

## Rung 2 — 200 members: not run

Pinned: 200 sessions, **114,400 total = 57,200 per family**, 170 changed
/ 30 stable, P and F cells. Not run in this pass. It is a
scale-validation rung ahead of the receipt rung; run it behind the host
lock with no compiler or daemon competitors:

```text
GEN_DUALSTACK=1 RELOADSTALL_DUALSTACK=1 N_PEERS=200 TOTAL_PREFIXES=114400 \
  CHANGED_PEERS=170 PROBE_PREFIXES="20.0.0.0/24 3001::/48" \
  ARTIFACTS_DIR=bench/scale/matrix/artifacts-dualstack-rung2-P \
  bash bench/scale/matrix/run-matrix.sh rustbgpd
GEN_DUALSTACK=1 GEN_FILTER_COUNT=64 RELOADSTALL_DUALSTACK=1 RELOADSTALL_FILTER_COUNT=64 \
  N_PEERS=200 TOTAL_PREFIXES=114400 CHANGED_PEERS=170 PROBE_PREFIXES="20.0.0.0/24 3001::/48" \
  ARTIFACTS_DIR=bench/scale/matrix/artifacts-dualstack-rung2-F \
  bash bench/scale/matrix/run-matrix.sh rustbgpd
```

## Rung 3 — 700 members: not run (needs a quiet window)

Pinned: 700 sessions, **400,400 total = 200,200 per family**, 600
changed / 100 stable, P and F cells, **two fresh runs of each** in one
quiet window on a pinned implementation. The driver enforces the host
lock, the quiet gate (1-minute load < 2.0, every CPU governor
`performance`, no compiler or daemon competitors, no swap movement), the
100 GiB tree-RSS abort, and the 300 s cool-down. Build the daemon,
`rbgp`, and the harness at the pinned commit first:

```text
cargo build --release --locked -p rustbgpd -p rustbgpctl
cargo build --release --locked --manifest-path bench/scale/reloadstall/Cargo.toml
for run in A B; do
  GEN_DUALSTACK=1 RELOADSTALL_DUALSTACK=1 N_PEERS=700 TOTAL_PREFIXES=400400 \
    CHANGED_PEERS=600 PROBE_PREFIXES="20.0.0.0/24 3001::/48" \
    ARTIFACTS_DIR=bench/scale/matrix/artifacts-dualstack-run$run-P \
    bash bench/scale/matrix/run-matrix.sh rustbgpd
  GEN_DUALSTACK=1 GEN_FILTER_COUNT=64 RELOADSTALL_DUALSTACK=1 RELOADSTALL_FILTER_COUNT=64 \
    N_PEERS=700 TOTAL_PREFIXES=400400 CHANGED_PEERS=600 PROBE_PREFIXES="20.0.0.0/24 3001::/48" \
    ARTIFACTS_DIR=bench/scale/matrix/artifacts-dualstack-run$run-F \
    bash bench/scale/matrix/run-matrix.sh rustbgpd
done
```

Expected duration, modeled from the IPv4-only 700 × 400,400 cells (not
observed for this shape): about 6–8 minutes per cell including the 300 s
cool-down, so roughly 30–35 minutes for the four cells, plus the quiet
gate's two 30 s samples per cell. Establishment and convergence at this
shape are unmeasured for dual-stack; the harness's 600 s first-output and
120 s no-progress watchdogs bound a stall.

## Honesty notes

- **rustbgpd only.** The BIRD and OpenBGPD generators are IPv4-only; a
  comparative claim needs the identical dual-stack input against pinned
  peer implementations and is not made here.
- **No IPv6 optimization promise.** The measured IPv6 recompute and
  distribution asymmetry recorded elsewhere stands as design evidence;
  nothing here changes the RIB.
- **Rung 1 is not a timing rung.** Its numbers are published as context
  for the correctness proof, from a busy host.
- **One IPv4 transport per member.** "Dual-stack" here is two negotiated
  families per session, the common IXP member shape; IPv6-transport
  sessions are a different shape and are not covered.
- The generated scenario carries the same RFC 8212 posture warning as the
  historical IPv4-only scenario (`config VALID, 1 WARNING`); it is
  pre-existing and unrelated to the families.
