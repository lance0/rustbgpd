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

**Import policy limitation:** `match_aspa_validation` only works in export
policy. Import policy evaluates in the transport layer before the route
reaches the RIB, where ASPA validation is applied. At import evaluation
time, `aspa_state` is always `Unknown`. This is the same limitation as
`match_rpki_validation` on import — both validation states are set
post-ingress in the RIB manager. rustbgpd rejects these validation-state
matches in import policy config rather than accepting inert statements.
Operators should use best-path demotion (step 0.7) for ASPA-based route
preference and export policy for hard rejection.

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
- `match_aspa_validation` (and `match_rpki_validation`) only work in export
  policy — import policy use is rejected at config load because validation
  runs post-ingress in the RIB manager
- Downstream verification is not supported — requires future per-peer
  relationship config
- RTR v2 version negotiation is implemented with automatic fallback to v1;
  ASPA is only available when the cache supports RTR v2
- No new config is needed for ASPA — it uses the same RTR cache servers
  as RPKI ROV
