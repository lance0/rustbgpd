# Per-peer RSS attribution and lazy RFC 8654 buffer receipt — 2026-07

This receipt corrects one over-broad inference in the July cross-stack
campaign and evaluates one bounded memory change.

The controlled result is:

- Under continuous churn, at fixed BASE route count, steady RSS grows by a
  measured **118.200 KiB/peer** at 10,000 BASE routes and **142.844 KiB/peer**
  at 100,000 BASE routes.
- Under the same continuous churn, at fixed peer count, steady RSS grows by a
  measured **825.515 B/BASE route** at 10 peers and **850.751 B/BASE route**
  at 100 peers.
- The earlier cross-stack 1.93 MiB/peer figure changed peer count and route
  count together. It remains a historical mixed-shape upper bound, not an
  estimate of isolated per-peer cost.
- Making the RFC 8654 receive buffer grow on demand removes an exact
  **6,150,300-byte** eager-reserve owner at 100 ordinary-message peers. The
  release C/N/N/C RSS delta is only **−185 KiB (−0.324%)**, below the
  predeclared 0.645% measurement floor, so **no RSS improvement is claimed**.

Every figure below is labelled by measurement surface. Release jemalloc gauges,
DHAT live heap, and Linux process RSS are different quantities and are not
substituted for one another.

## Question and control

The [cross-stack bgperf2
receipt](competitive-bgperf2-2026-07.md) compared 10 peers × 1,000 routes with
100 peers × 1,000 routes. Both peer count and total route count grew tenfold,
so its computed 1.93 MiB/peer marginal folded route storage into the numerator.
Two other cells happened to share a 212.0 MiB median despite different shapes,
but the run-to-run RSS spread was 24% at one of them. That evidence identified
a memory problem; it did not isolate its dimension.

This campaign uses the real release daemon and real `reloadstall` BGP clients,
with two counterbalanced repeats of a 2 × 2 matrix:

| Peers | BASE routes | BASE routes per peer | Explain | Reloads |
|---:|---:|---:|:---:|---:|
| 10 | 10,000 | 1,000 | off | 0 |
| 10 | 100,000 | 10,000 | off | 0 |
| 100 | 10,000 | 100 | off | 0 |
| 100 | 100,000 | 1,000 | off | 0 |

The control is clean commit
`5c4fdc8f9cf64177af75b47f9afe77f23aca963c`, tree
`2b6bd7e57a2c753033d35b57a18fbf221aca9dd2`. The execution order was
10/10k, 10/100k, 100/10k, 100/100k, then the exact reverse. Every cell uses
one homogeneous IPv4-unicast update group and runs a 30-second control window.
After base convergence, the last 8 stubs each continuously flap a distinct
16-prefix block every 125ms. The route-count labels above are BASE totals, not
point-in-time holdings.

## Environment and acceptance

The host has an AMD Ryzen Threadripper 7970X (32 cores / 64 threads), 125 GiB
RAM, Linux 6.17, Rust 1.97.0, and the `performance` governor on every online
CPU. Every pre-build and post-build admission row records no competing
rustbgpd build or harness, no swap-counter movement, a free port range, and
ample available memory. This is one-host evidence and does not predict another
allocator, kernel, or machine.

Every accepted release run:

- exits successfully with both harness and RSS sampler at zero;
- reaches exactly 10/10 or 100/100 Established sessions;
- records at least BASE minus the observer's own base slice in accumulated base
  announcements for every observer; this is not a unique-prefix or final
  holdings proof;
- reports exactly one update group, zero parse errors, zero exact-export
  rejections, and zero final outbound queue depth;
- uses the real release binary, `EXPLAIN=false`, and `RELOADS=0`.

The committed final metrics snapshots, process snapshots, 1 Hz RSS streams,
preflights, and provenance make those gates independently checkable.

## Controlled peer and route slopes

Steady RSS is the median of the post-convergence 1 Hz process-tree samples
while the eight churn blocks continue toggling. Each table cell is the mean of
its two counterbalanced repeats. The final Adj-RIB-In total is the sum of
`bgp_rib_prefixes{afi_safi="all"}` in that run's retained final metrics
snapshot:

| Peers | BASE routes | Run 1 RSS / final routes | Run 2 RSS / final routes | Mean RSS (KiB) |
|---:|---:|---:|---:|---:|
| 10 | 10,000 | 46,394 / 10,000 | 46,462 / 10,032 | 46,428 |
| 10 | 100,000 | 118,918 / 100,000 | 119,048 / 100,016 | 118,983 |
| 100 | 10,000 | 57,250 / 10,016 | 56,882 / 10,016 | 57,066 |
| 100 | 100,000 | 131,576 / 100,016 | 132,102 / 100,096 | 131,839 |

The largest same-cell spread is 0.645%, so a third repeat was not invoked.

Holding BASE routes fixed:

| Fixed BASE routes | 10-peer mean | 100-peer mean | Computed slope |
|---:|---:|---:|---:|
| 10,000 | 46,428 KiB | 57,066 KiB | **118.200 KiB/peer** |
| 100,000 | 118,983 KiB | 131,839 KiB | **142.844 KiB/peer** |

Holding peer count fixed:

| Fixed peers | 10k-route mean | 100k-route mean | Computed slope |
|---:|---:|---:|---:|
| 10 | 46,428 KiB | 118,983 KiB | **825.515 B/BASE route** |
| 100 | 57,066 KiB | 131,839 KiB | **850.751 B/BASE route** |

The controlled matrix does not support “memory tracks peers, not routes.”
Both dimensions are material, and at these shapes BASE route count contributes
the larger absolute change. These slopes are local finite differences under
the same continuous-churn workload, not a linearity claim or a sizing formula
beyond the measured 10–100 peer and 10k–100k BASE-route bounds.

## DHAT attribution

One symbolized `release-prof` DHAT control at 10 peers and another at 100 peers
use the same 10,000 BASE routes. Their raw bytes live at the process-wide heap
maximum are 24,975,947 and 39,887,660, while their point-in-time final
Adj-RIB-In totals are 10,080 and 10,064. Continuous churn and different final
holdings make the total and component deltas descriptive only; this receipt
makes no total-heap or aggregate-component attribution from them.

The causal evidence is the exact normalized owner:

```text
ReadBuffer::set_max_message_len
```

It grows from 615,030 to 6,150,300 bytes, exactly 61,503 bytes (60.0615 KiB)
per peer. RFC 8654 raises the accepted inbound message limit from 4096 to
65,535 bytes after negotiation. The control implementation immediately
reserved the difference for every session, even when every UPDATE remained
below 4096 bytes.

Other owner rows remain in the retained derivative, but their aggregate deltas
are not attributed to peer count or this change.

## Lazy-buffer candidate

Candidate `b40ec3e8b50774c0257166bf06812be84f47df8e`, tree
`9db9dddcf01d73bf8328dbc435b0b99572583568`, raises only the logical accepted
message limit. `BytesMut` grows when bytes actually arrive.

The immediate-parent release comparison uses 100 peers × 100 BASE routes
(10,000 BASE total), C/N/N/C order, 30 seconds, continuous churn, and the same
acceptance gates:

| Order | Build | Steady RSS (KiB) | jemalloc allocated (B) | Final Adj-RIB-In |
|---:|---|---:|---:|---:|
| 1 | control | 57,200 | 41,190,808 | 10,016 |
| 2 | candidate | 57,140 | 35,669,640 | 10,000 |
| 3 | candidate | 56,772 | 35,021,408 | 10,000 |
| 4 | control | 57,082 | 41,237,448 | 10,016 |
| **mean** | **control** | **57,141** | **41,214,128** | |
| **mean** | **candidate** | **56,956** | **35,345,524** | |
| **raw delta** | | **−185 (−0.324%)** | **−5,868,604 (−14.24%)** | |

The mean RSS delta is below the larger of the immediate 0.207% control spread
and the predeclared 0.645% same-cell floor, so it carries **no resident-memory
claim**.

The jemalloc gauges are point snapshots taken at different churn phases and
different final route totals. Their raw delta is retained but carries **no
attributable allocator-total claim**. The independent DHAT pair has the same
confounder: its control final Adj-RIB-In total is 10,064 and its candidate
total is 10,000. Its raw component table is:

| DHAT component | Control live bytes | Candidate live bytes | Delta |
|---|---:|---:|---:|
| Total heap | 39,887,660 | 34,150,991 | −5,736,669 (−14.38%) |
| Transport session buffers/scratch | 7,615,149 | 1,459,093 | −6,156,056 |
| Exact eager-reserve owner | 6,150,300 | **0** | **−6,150,300** |

The total and aggregate component deltas are descriptive only. The exact
production allocation the patch removes is absent from the candidate under a
normalized owner stack that names the changed production function. That
6,150,300 → 0 row, together with the code path and destructive red proof, is
the only causal allocation claim.

## Correctness and load-bearing proof

The code change is deliberately smaller than the measurement:

- `extended_limit_does_not_eagerly_grow_buffer` asserts the 4096-byte initial
  allocation survives raising the logical limit.
- `maximum_extended_message_grows_and_decodes_byte_exactly` constructs and
  decodes a full 65,535-byte Notification, proving on-demand growth and exact
  raw-byte retention.
- `inbound_extended_message_accepted_from_peer_without_capability` sends a
  greater-than-4096-byte, 1,100-prefix UPDATE through a real connected TCP
  socket and the production `read_tcp` path. It proves the buffer stays small
  through negotiation, grows only after bytes arrive, the session remains
  Established with all 1,100 routes, and BMP receives the original UPDATE PDU
  byte for byte.

The destructive proof restores the eager `reserve`. The fully-qualified
real-session test then fails at:

```text
negotiating the extended inbound limit must not eagerly grow the buffer
```

with 61,439 bytes of remaining capacity instead of 4,096. This directly makes
the structural guard red on the production break it protects.

## Costs and limits

- This is not a cap reduction. A legal extended message remains accepted.
- A peer that actually sends a message larger than 4096 bytes grows the buffer
  on demand. The allocation stays at its high-water capacity for the lifetime
  of that session object, including reconnects on the same object, so the
  saving can approach zero for extended-message-heavy peers.
- Only IPv4 unicast, one homogeneous update group, explain disabled, and zero
  reloads were measured. There is no throughput, convergence, query-latency,
  IPv6, VPN, Add-Path, heterogeneous-policy, or cross-host claim.
- DHAT runs use a profiling allocator. Only the exact changed-function owner
  establishes causal allocation removal; aggregate bytes do not establish
  release RSS or a total-heap improvement.

## Reproduction and artifacts

The sanitized immutable artifact set is
[`artifacts/per-peer-rss-attribution-2026-07/`](artifacts/per-peer-rss-attribution-2026-07/README.md).
It retains all release summaries and raw sample streams, complete final metrics,
preflights, commit/tree provenance, lossless DHAT derivatives, recomputation
tables, commands, toolchain, binary hashes, and checksums. Raw DHAT JSON is
intentionally excluded because it carries instruction addresses and runtime
arguments; the normalized derivative is sufficient for the in-tree classifier
to rebuild every component total.
