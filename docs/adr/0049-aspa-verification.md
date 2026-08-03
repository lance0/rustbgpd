# ADR-0049: ASPA Path Verification

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

### Role-aware verification

ASPA verification is selected from the configured BGP Role (RFC 9234), matching
draft-ietf-sidrops-aspa-verification-27 §6.3:

- local role `customer` (routes received from a provider) uses downstream
  verification (§5.5);
- local roles `provider`, `peer`, `rs`, and `rs-client` use upstream
  verification (§5.4);
- no configured role preserves the original upstream-only behavior.

The role-selected context is stored on each unicast route so ASPA cache updates
can revalidate with the same direction used at import time.

### Verification algorithm

Per draft-ietf-sidrops-aspa-verification-27:

1. Compress AS_PATH: flatten segments, remove consecutive duplicates
2. Empty AS_PATH -> Invalid (per spec step 1)
3. The most recently added AS must match the neighbor ASN, with the
   transparent route-server-client exception for upstream verification
4. AS_SET present -> Invalid (path is unverifiable)
5. Single-hop -> Valid (no pairs to verify)
6. Upstream verification walks from origin toward neighbor, checking each hop:
   - ProviderPlus -> authorized, continue
   - NotProviderPlus -> Invalid (proven route leak)
   - NoAttestation -> mark incomplete, continue
7. Downstream verification computes the §5.3 up-ramp and down-ramp bounds:
   - `max_up_ramp + max_down_ramp < N` -> Invalid
   - `min_up_ramp + min_down_ramp < N` -> Unknown
   - otherwise -> Valid

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
policy against real validation states. Routes arriving before the first ASPA
table loads have `aspa_state = Unknown`; later ASPA cache updates revalidate
admitted routes in the RIB and trigger inbound Route Refresh for established
peers whose resolved import policy matches ASPA state, so previously denied
routes can be reconsidered against the fresh snapshot.

### RIB re-validation on ASPA table update

When a new ASPA table arrives, the RibManager re-validates all routes
by running the role-aware verification algorithm on each route's AS_PATH.
Routes whose ASPA state changes are added to the recompute set and
best-path re-runs for affected prefixes. Same pattern as RPKI
re-validation.

### Route.aspa_state field

Routes carry `aspa_state: AspaValidation` (default: Unknown) and the compact
`AspaValidationContext` needed to replay the same role-aware verification on
ASPA table changes. Set on ingress and updated on ASPA table changes.

## Consequences

- Without ASPA configured (no RTR v2 cache), all routes remain Unknown
  and best-path step 0.7 is a no-op tie
- ASPA table updates trigger full re-validation — acceptable since cache
  updates are infrequent
- The wire crate gains public ASPA validation state/context types (minor semver
  bump when published)
- `match_aspa_validation` (and `match_rpki_validation`) work in both import
  and export policy — import evaluation uses the current validation snapshot
  and validation-cache updates trigger targeted import-policy refresh for
  dependent established peers
- RTR v2 version negotiation is implemented with automatic fallback to v1;
  ASPA is only available when the cache supports RTR v2
- No new ASPA-specific config is needed — it uses the same RTR cache servers
  as RPKI ROV and the existing BGP Roles configuration to select direction
- iBGP routes deliberately carry `Unknown`: ASPA is an edge-ingress signal,
  and draft -27 §6.2 says its use on internal sessions is NOT RECOMMENDED

## Amendments

### 2026-05-27 — Algorithm fidelity + §6.2 family gate (PR #294)

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

### 2026-06-03 — Role-aware full-scope verification

The original upstream-only scope is extended to the full draft-v25 verifier:

- `AspaValidationContext` records neighbor ASN, local BGP Role, and the
  transparent-IX first-AS exception needed to replay ASPA validation later.
- `ValidationSnapshot::validate_aspa` selects upstream or downstream
  verification from the local BGP Role. A local `customer` role means routes are
  received from a provider and use downstream verification; all other roles use
  upstream verification. If no role is configured, rustbgpd preserves the
  original upstream-only behavior.
- The draft-v25 first-AS precondition is enforced for role-aware validation.
  The upstream route-server-client exception is represented by
  `first_as_check_exempt`.
- RIB cache-update revalidation now uses each route's stored ASPA context, so
  downstream routes do not silently fall back to upstream verification when a
  fresh RTR table arrives.

Remaining ASPA work is test hardening, not feature scope. A compact offline
subset of the NIST-BRIO ASPA demo corpus (b7.1.2) now pins upstream and
downstream Valid / Invalid / Unknown verifier outcomes, including the documented
ASPA-Valid forged-origin / forged-segment limitations. Keep expanding focused
`match_aspa_validation` policy coverage as demand warrants.

### 2026-08-03 — Edge-ingress applicability and RFC 6793 peers

The implementation is aligned with
`draft-ietf-sidrops-aspa-verification-27` on three applicability boundaries:

- The §5 neighbor-AS check applies to eligible eBGP unicast routes even when no
  BGP Role is configured. Roleless sessions continue to use upstream
  verification; configured roles select upstream versus downstream verification
  and are not a prerequisite for the neighbor-AS check. A local
  `rs-client` remains exempt for a transparent IX as required by §5.
- A peer that did not negotiate the four-octet-AS capability is not exempt.
  rustbgpd is the RFC 6793 NEW speaker and applies the check to the effective
  AS_PATH after `AS_PATH` / `AS4_PATH` reconstruction.
- IPv4/IPv6-unicast routes learned over iBGP are assigned `Unknown` before
  import policy. Initial insertion and later ASPA-cache revalidation preserve
  that state. This is rustbgpd's edge-ingress policy based on draft -27 §6.2's
  NOT RECOMMENDED language, not a protocol MUST.

The first two corrections can newly treat a roleless or RFC 6793 OLD-peer
eBGP UPDATE with a mismatched first AS as withdraw. The iBGP correction can
change prior ASPA-derived best-path rankings by replacing computed Valid or
Invalid states with Unknown; no best-path algorithm or retention rule changed.
