# ADR-0049: ASPA Upstream Path Verification

**Status:** Accepted
**Date:** 2026-03-13

## Context

ASPA (Autonomous System Provider Authorization) is the next major routing
security feature after RPKI origin validation. It validates AS_PATH topology
by checking customer-provider relationships, addressing route leaks that
RPKI ROV cannot detect. RIPE and ARIN support ASPA object publishing in
production (January 2026), Cloudflare has deployed ASPA verification globally,
and the IETF draft is targeted for IESG submission in March 2026.

BIRD and OpenBGPd have ASPA implementations. Market research identified
this as the highest-priority near-term feature for rustbgpd.

The existing RPKI ROV infrastructure (ADR-0034) provides a proven pattern:
RTR client -> VrpManager -> Arc<Table> snapshot -> RIB revalidation ->
best-path -> policy. ASPA follows this pattern with different data types
and a different verification algorithm.

## Decision

### AspaValidation enum in wire crate

```rust
pub enum AspaValidation {
    Valid,
    Invalid,
    #[default]
    Unknown,
}
```

Placed in `rustbgpd-wire` alongside `RpkiValidation`. These are
routing-domain result enums, not wire-format concepts — they live in wire
because it is the lowest common dependency shared by rib, policy, and
transport. Documented as temporary placement pending a future domain-types
crate if more shared non-wire types accumulate.

### ASPA data model: AspaRecord + AspaTable

```rust
struct AspaRecord {
    customer_asn: u32,
    provider_asns: Vec<u32>,  // sorted ascending
}

struct AspaTable {
    records: HashMap<u32, Vec<u32>>,  // customer -> sorted providers
}
```

`AspaTable::authorized(customer, provider) -> ProviderAuth` uses binary
search on the sorted provider list. Multiple records for the same customer
ASN are merged (union of provider sets), matching RTR cache behavior where
multiple CAs may issue ASPAs for the same customer.

`Arc<AspaTable>` follows the same immutable snapshot pattern as `Arc<VrpTable>`.

### Upstream-only verification (initial scope)

Only upstream path verification is implemented. This covers routes from
customers and peers — the common case and the IX route server use case.

Downstream verification (routes from providers) requires a per-peer
`relationship` config field (customer/provider/peer) and a second algorithm
variant. Deferred to a follow-up.

### Verification algorithm

Per draft-ietf-sidrops-aspa-verification:

1. Compress AS_PATH: flatten segments, remove consecutive duplicates
2. AS_SET present -> Invalid (path is unverifiable)
3. Empty AS_PATH -> Invalid (per spec step 1)
4. Single-hop -> Valid (no pairs to verify)
5. Walk from origin toward neighbor, checking each hop:
   - ProviderPlus -> authorized, continue
   - NotProviderPlus -> Invalid (proven route leak)
   - NoAttestation -> mark incomplete, continue
6. If any hop was NoAttestation -> Unknown; otherwise -> Valid

Invalid trumps Unknown: a single proven non-provider hop makes the entire
path Invalid regardless of missing attestations elsewhere.

### RTR version 2 support

ASPA records are delivered via RTR v2 (draft-ietf-sidrops-8210bis), which
adds the ASPA PDU (type 11). The codec now accepts both v1 and v2 PDUs
based on the version byte in the header.

ASPA PDU wire format per draft-ietf-sidrops-8210bis:
```
byte 0:     version (2)
byte 1:     type (11)
byte 2:     flags (bit 0 = announce/withdraw)
byte 3:     zero
bytes 4-7:  length (12 + 4 * num_providers)
bytes 8-11: customer ASN
bytes 12+:  provider ASNs (4 bytes each)
```

Provider count is derived from the length field: `(length - 12) / 4`.
There is no explicit provider count field in the PDU.

Version negotiation: each fresh connection attempt starts with v2. If the
server responds with ErrorReport code 4 (Unsupported Protocol Version), the
client falls back to v1 and retries immediately for that attempt. On later
reconnects it probes v2 again. When running at v1, ASPA PDUs are not received
and all routes remain `Unknown`. The fallback is logged at info level.

### Extend VrpManager (not separate AspaManager)

ASPA records arrive in the same RTR data stream as VRPs. The VrpManager
is extended with parallel ASPA state:

- `server_aspa_tables: HashMap<SocketAddr, Vec<AspaRecord>>`
- `current_aspa_table: Arc<AspaTable>`
- `AspaTableUpdate` sent to RIB on a separate channel

This avoids a second manager task and keeps the channel topology simple.
The merge logic is identical: per-server tables, set union, rebuild on
change, skip distribution if unchanged.

### Best-path step 0.7: ASPA preference

ASPA integrates between RPKI (step 0.5) and LOCAL_PREF (step 1):

- Valid (2) > Unknown (1) > Invalid (0)

Same pattern as RPKI: Invalid routes are deprioritized but not dropped.
Hard rejection uses policy: `match_aspa_validation = "invalid"` +
`action = "deny"`.

### Policy match_aspa_validation

Policy statements gain an optional `match_aspa_validation` field, following
the exact `match_rpki_validation` pattern. Enables:
- Rejecting ASPA-invalid routes on export
- Tagging ASPA-valid routes with communities on export
- Setting LOCAL_PREF based on ASPA state on export

**Import policy note:** `match_aspa_validation` (and `match_rpki_validation`)
work in both import and export policy. Transport sessions receive the
current validation snapshot via `tokio::sync::watch` and evaluate import
policy against real validation states. However, import validation is
**best-effort against the current snapshot**: routes arriving before the
first ASPA table loads will have `aspa_state = Unknown`, and later cache
updates do not retroactively re-filter already-admitted routes — the RIB
revalidates and recomputes best-path but does not re-run import policy.
For convergent behavior, prefer best-path demotion (step 0.7) over import
policy filtering. Use `match_aspa_validation = "invalid"` + `action =
"deny"` on import as an early discard optimization, not as a sole defense.

### RIB re-validation on ASPA table update

When a new ASPA table arrives, the RibManager re-validates all routes
by running the upstream verification algorithm on each route's AS_PATH.
Routes whose ASPA state changes are added to the recompute set and
best-path re-runs for affected prefixes. Same pattern as RPKI
re-validation.

### Route.aspa_state field

Routes carry `aspa_state: AspaValidation` (default: Unknown). Set on
ingress and updated on ASPA table changes.

## Consequences

- Without ASPA configured (no RTR v2 cache), all routes remain Unknown
  and best-path step 0.7 is a no-op tie
- ASPA table updates trigger full re-validation — acceptable since cache
  updates are infrequent
- The wire crate gains one new public enum (minor semver bump when
  published)
- `match_aspa_validation` (and `match_rpki_validation`) work in both import
  and export policy — import evaluation uses the current validation snapshot
  (best-effort, see KNOWN_ISSUES.md)
- Downstream verification is not supported — requires future per-peer
  relationship config
- RTR v2 version negotiation is implemented with automatic fallback to v1;
  ASPA is only available when the cache supports RTR v2
- No new config is needed for ASPA — it uses the same RTR cache servers
  as RPKI ROV

## Amendments

### 2026-05-27 — Algorithm fidelity + §6.2 family gate (PR #TBD)

ADR retargeted from `draft-ietf-sidrops-aspa-verification` (IESG-
submission state at original ADR write) to
`draft-ietf-sidrops-aspa-verification-25` (April 19, 2026). Two
correctness updates:

**§5.4 algorithm equivalence (no production code change).** The
draft describes upstream verification in §5.3 as a bounds-checker
that computes `max_up_ramp` and `min_up_ramp` walking from origin
toward neighbor. For *upstream* verification (§5.4 with
`max_down_ramp = min_down_ramp = 0`), the bounds form collapses
into the pairwise walk this ADR specifies. The equivalence is
empirically verified by `spike_bounds_equivalence_on_synthetic_corpus`
in `crates/rpki/src/aspa_verify.rs`, which exhaustively cross-
products distinct-ASN paths of length 2..=5 drawn from a 6-ASN pool
with every per-pair attestation state (≈ 69k cases). A
`#[cfg(test)]` reference implementation of the bounds-checker stays
in tree as a regression oracle — any future spec revision that
breaks the equivalence (e.g. a non-zero `max_down_ramp`) surfaces at
PR time.

**§6.2 per-AFI/SAFI family gate.**
`ValidationSnapshot::validate_aspa` now takes an `(Afi, Safi)`
parameter and returns `Unknown` immediately for any family outside
`(IPv4 | IPv6, Unicast)`. Previously, the ASPA verdict was computed
once per UPDATE from the shared AS_PATH and propagated to every NLRI
in the UPDATE — including FlowSpec, EVPN, and other non-unicast
families that the draft explicitly excludes from ASPA. Operators
using `match_aspa_validation` import policy against non-unicast
families will now see `Unknown` instead of unsafely inheriting the
upstream walk's verdict. IPv4 / IPv6 unicast routes are unchanged.

**Still deferred (not closed by this PR):**

- Downstream verification (routes from providers) per §5.5.
  Requires per-peer relationship configuration; remains deferred —
  see "Upstream-only verification (initial scope)" above for the
  original rationale.
- Automatic import-policy re-validation on validation-cache update.
  Best-path demotion still provides convergent semantics; the sharp
  edge documented in KNOWN_ISSUES.md and CONFIGURATION.md remains.
- Draft v25 §5.4 step 2 first-AS precondition: the most-recent AS in
  the `AS_PATH` MUST equal the negotiated neighbor ASN, with a
  transparent-route-server-client exception. rustbgpd has no
  `enforce-first-as`-equivalent today; tracked as a follow-up. ASPA
  verdicts against peers that strip or rewrite the leftmost AS may
  be misleading until this lands.
