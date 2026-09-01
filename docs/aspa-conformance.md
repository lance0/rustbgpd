# ASPA conformance and route-server positioning

> **Document class: REFERENCE.** This maintained page defines a contract, specification, or reusable procedure; follow any stated version scope.

Per-procedure conformance of rustbgpd's ASPA implementation against
[draft-ietf-sidrops-aspa-verification-27](https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-verification-27),
with the RTR transport rows against draft-ietf-sidrops-8210bis. Every
row cites the code, test, or interop receipt that backs its status, and
a "Partial" row says exactly what is and is not implemented.

The one-line summary: rustbgpd implements the draft-27 verification
procedures with role-aware direction selection and detailed
diagnostics, and is deliberately **Partial on §5.6
mitigation/retention** — validation outcomes are surfaced for explicit
operator policy; the daemon does not ship default rejection
enforcement or lossless Adj-RIB-In retention.

## Implemented revisions

- **draft-ietf-sidrops-aspa-verification-27** (20 July 2026) — the
  implemented revision is the current revision. The -26→-27 delta was
  editorial; the meaningful -25→-26 clarifications
  (consecutive-duplicate compression, semantic-invalid first-AS
  handling) are implemented and covered below.
- **draft-ietf-sidrops-8210bis-27** (13 August 2026) — the RTR client's
  ASPA transport is drift-checked against revision 27. PDU type assignments
  remain unchanged (End of Data 7, Cache Reset 8, ASPA 11), and the prior
  session-version and malformed-ASPA tightenings remain implemented. Revision
  27 also requires a router client to reject noncanonical host bits in IPv4
  and IPv6 Prefix PDUs; that negotiated-v2 boundary is implemented below.
  The new paragraph labels Error Code 1 as "Corrupt Data" even though the
  draft's registry assigns Corrupt Data to code 0, so rustbgpd follows the
  internally consistent registry value.

**Refresh trigger:** re-verify this page when either draft is
published as an RFC, and review the revision delta whenever either
draft publishes a new revision. A delta that changes a normative
requirement cited below reopens the affected row; each row's evidence
column names the receipt to re-check against the new text.

## Verification procedures (draft-ietf-sidrops-aspa-verification-27)

| # | Section | Requirement | Status | What exists | Evidence |
|---|---------|-------------|--------|-------------|----------|
| 1 | §5 | First-AS precondition: the most recently added AS must be the neighbor AS; a semantically invalid path uses RFC 7606 treat-as-withdraw | Implemented | Enforced on eligible eBGP IPv4/IPv6-unicast UPDATEs even with no BGP Role configured, before policy or cache state can influence the disposition. The exemption applies only when this speaker has the local `rs-client` Role; `route_server_client = true` identifies a remote member and remains checked. An RFC 6793 OLD peer is checked against the reconstructed effective AS_PATH, not exempted. | `aspa_first_as_mismatch` in `crates/transport/src/session/inbound.rs` · `crates/transport/src/session/tests/rpki_aspa.rs` · [ADR-0049](adr/0049-aspa-verification.md) 2026-08-19 amendment |
| 2 | §5.1–§5.2 | Provider authorization function `authorized(customer, provider)` over the merged Set of Provider ASes | Implemented | `AspaTable::authorized` returns Provider+ / Not Provider+ / No Attestation from binary search on sorted provider sets; multiple records for one customer merge as a union across caches, with 8210bis replacement semantics within one cache. | `crates/rpki/src/aspa.rs` |
| 3 | §5.4/§5.5 preamble | Path preparation: AS4_PATH reconstruction, consecutive-duplicate compression, AS_SET makes the path unverifiable (Invalid), empty AS_PATH Invalid, single-hop Valid | Implemented | `compress_as_path` flattens segments and removes consecutive duplicates, returns Invalid on any AS_SET; verification runs on the post-reconstruction effective path. | `crates/rpki/src/aspa_verify.rs` · reconstruction in `crates/transport/src/session/inbound.rs` |
| 4 | §5.3 | Up-ramp / down-ramp bounds computation | Implemented | Downstream verification computes `max_up_ramp` / `min_up_ramp` / `max_down_ramp` / `min_down_ramp` directly per §5.3. Upstream uses the equivalent pairwise walk; the equivalence to the §5.3 bounds form is exhaustively verified by a 69,210-case synthetic corpus with a bounds-checker reference implementation kept in-tree as a regression oracle. | `spike_bounds_equivalence_on_synthetic_corpus` in `crates/rpki/src/aspa_verify.rs` |
| 5 | §5.4 | Upstream verification (routes from customers, lateral peers, RS, RS-clients) | Implemented | Full procedure including the local RS-client-role first-AS exemption. Outcomes pinned by unit tests including an offline subset of the NIST-BRIO ASPA demo corpus (b7.1.2), and end-to-end against FRR with an RTR v2 cache. | `crates/rpki/src/aspa_verify.rs` · M27 row in [INTEROP.md](INTEROP.md) |
| 6 | §5.5 | Downstream verification (routes from providers) | Implemented | Selected when the local BGP Role is `customer`; §5.3 bounds evaluation with the downstream Invalid/Unknown/Valid inequalities. Proven end-to-end: downstream-Valid and downstream-Invalid verdicts asserted over gRPC in a containerlab topology. | `verify_downstream_detailed` in `crates/rpki/src/aspa_verify.rs` · M59 row in [INTEROP.md](INTEROP.md) |
| 7 | §5.6 | Mitigation: Invalid SHOULD be ineligible for selection and MUST be kept in Adj-RIB-In for re-evaluation; Unknown SHOULD get the same preference as Valid | **Partial** | Validation outcomes are computed, stored, revalidated on every cache update, and fully surfaced to policy and diagnostics — but selection keeps the shipped `Valid > Unknown > Invalid` ranking, Invalid stays eligible unless operator policy denies it, and there is no lossless Adj-RIB-In retention. Detailed below. | [ADR-0123](adr/0123-aspa-v27-mitigation-and-retention.md) · `aspa_preference` in `crates/rib/src/best_path.rs` |
| 8 | §6.2 | Apply only to {IPv4, unicast} and {IPv6, unicast}; MUST NOT other families by default; edge-ingress; NOT RECOMMENDED on iBGP | Implemented | The family gate returns Unknown for any non-unicast family; iBGP-learned unicast routes are assigned Unknown before import policy and keep that state across cache revalidation. | `ValidationSnapshot::validate_aspa` in `crates/rpki/src/lib.rs` · `validate_route_aspa` in `crates/rib/src/manager/helpers.rs` · `crates/rib/src/manager/tests/rpki.rs` |
| 9 | §6.3 | RFC 9234 BGP Roles RECOMMENDED to select upstream vs downstream procedures | Implemented | Roles with the OPEN cross-check are implemented; the configured local Role selects the verification direction (`customer` → downstream, all others and roleless → upstream), and the role-selected context is stored per route so revalidation replays the same direction. | `direction_for_role` in `crates/rpki/src/aspa_verify.rs` · [ADR-0071](adr/0071-bgp-roles-otc.md) · M59 row in [INTEROP.md](INTEROP.md) |
| 10 | §6.4 | Complex peering: choose the algorithm per session; optionally per prefix | **Partial** | Per-session selection is implemented — direction follows each peer's configured Role, so segregated complex relations (separate sessions per relationship) work as the draft describes. Per-prefix algorithm selection on a single unsegregated session is not implemented. | Per-peer `role` in [CONFIGURATION.md](CONFIGURATION.md) |
| 11 | §6.6 | Causes of Invalid AS_PATH SHOULD be logged | Implemented | The verifier retains the first proven Not Provider+ hop; first-AS failures log structured warnings; an ASPA cache refresh emits one bounded top-eight Invalid summary; per-route ASPA state and the invalid hop are retained in the rejected-routes store, queryable via `ListRejectedRoutes` / `rbgp rib received <peer> --rejected`. | `verify_detailed` in `crates/rpki/src/aspa_verify.rs` · `crates/transport/src/session/rejected_routes.rs` · rejection table in [OPERATIONS.md](OPERATIONS.md) |
| 12 | §8.4 | OTC-based procedures RECOMMENDED to complement ASPA | Implemented | RFC 9234 Only-to-Customer attribute handling ships alongside Roles. | [ADR-0071](adr/0071-bgp-roles-otc.md) |
| 13 | §4, §6.5 | ASPA registration and AS-migration guidance | Not applicable | Operator/CA-side process recommendations with no router implementation requirement. | — |

### What "Partial" means for §5.6

Implemented:

- Verification runs at edge ingress; every eligible route carries its
  ASPA state, and every ASPA dataset change revalidates admitted
  routes (`handle_aspa_cache_update` in
  `crates/rib/src/manager/graceful_restart.rs`).
- Policy can act on the state in both import and export:
  `match_aspa_validation` in TOML policy and `route.aspa` in `.rpol`
  ([rpol-language.md](rpol-language.md)). One explicit deny statement
  makes Invalid ineligible.
- Cache updates trigger targeted inbound Route Refresh for
  established peers whose import policy depends on ASPA
  (`soft_reset_import_validation_dependents` in
  `src/peer_manager/policy.rs`,
  `bgp_validation_import_refreshes_total` metric), so
  previously denied routes are re-evaluated against the fresh
  snapshot.
- Best path deprioritizes Invalid: step 0.7 ranks
  `Valid > Unknown > Invalid` between RPKI and LOCAL_PREF
  (`crates/rib/src/best_path.rs`).

Not implemented:

- **Default ineligibility of Invalid.** Invalid routes remain
  selectable when no better candidate exists, unless operator policy
  denies them.
- **Valid/Unknown preference parity.** rustbgpd ranks Valid above
  Unknown; §5.6 says Unknown SHOULD be treated at the same preference
  level as Valid.
- **Lossless Adj-RIB-In retention.** §5.6 requires a route made
  ineligible to be kept for future re-evaluation (RFC 9324 records
  the same retention reasoning for drop policies). rustbgpd's
  rejected-routes store is a bounded, lossy diagnostic LRU — it
  answers "why was this rejected", it cannot reproduce the route.
  Re-evaluation of policy-rejected routes relies on inbound Route
  Refresh from the peer.

This is a deliberate posture, not a gap awaiting a quick fix. As with
RFC 8212 handling ([ADR-0112](adr/0112-rfc-8212-ebgp-requires-policy.md),
[ADR-0119](adr/0119-rfc-8212-secure-default-config-epoch.md)), the
daemon surfaces validation facts and leaves eligibility changes to
explicit operator policy — the appropriate default for a route server,
where rejection decisions belong to the operator and their members.
[ADR-0123](adr/0123-aspa-v27-mitigation-and-retention.md) accepts the
§5.6 target and gates activation on a lossless pre-policy Adj-RIB-In
view: Invalid ineligibility and Valid/Unknown parity will activate
together behind that gate or not at all, because an intermediate
ranking would create a behavior epoch without satisfying the draft's
complete mitigation.

## ASPA transport over RTR v2 (draft-ietf-sidrops-8210bis-27)

| # | Requirement | Status | What exists | Evidence |
|---|-------------|--------|-------------|----------|
| 1 | ASPA PDU (type 11) decode with §5.12 shape enforcement | Implemented | Announce requires at least one provider, strictly increasing order, no AS 0 among multiple providers; withdraw requires no provider list and PDU length exactly 12; violations draw Error Report code 9. | §5.12 tests in `crates/rpki/src/rtr_client.rs` |
| 2 | §5.12 replacement semantics | Implemented | Within one cache an announcement replaces the customer's provider set (never merges) and a withdrawal removes the customer ASN; proven live, including a valid→invalid REPLACE that a merge would have left valid. | `crates/rpki/src/aspa.rs` · M84 row in [INTEROP.md](INTEROP.md) |
| 3 | §7 version negotiation with v1 fallback | Implemented | Each fresh connection probes v2; an Unsupported Protocol Version error lands v1 for that attempt. At v1 no ASPA PDUs arrive and routes stay Unknown. Proven against StayRTR (v1-only) alongside Routinator (v2) and a deterministic v2 ASPA source. | M84 row in [INTEROP.md](INTEROP.md) |
| 4 | Per-cache session/serial epoch with retention across resync | Implemented | Cache state is one per-cache `(version, session ID, serial)` epoch advanced only at validated End of Data; identity mismatches force a Reset Query resync while validated data (including ASPA) is retained until replaced or expired. | M84 row in [INTEROP.md](INTEROP.md) · [RTR notes in RFC_NOTES.md](RFC_NOTES.md#rfc-6811--rpki-origin-validation--rfc-8210--rtr) |
| 5 | §5.9/§5.10 canonical Prefix PDU network addresses | Implemented | Under negotiated v2, IPv4 and IPv6 Prefix PDUs with nonzero host bits are fatal corrupt data: the client sends Error Report code 0 with the offending frame, closes, flushes that cache's previously learned data, and publishes none of the incomplete transaction. RTR v1 decoding remains compatible. | Codec boundary tables and end-to-end client test in `crates/rpki/src/rtr_codec.rs` and `crates/rpki/src/rtr_client.rs` |

The full RTR conformance notes — timer bounds, error-code
dispositions, and the two documented deviations (Error Codes 6 and 7
are not detected) — live in
[RFC_NOTES.md](RFC_NOTES.md#rfc-6811--rpki-origin-validation--rfc-8210--rtr).

## Route-server rollout positioning

For an exchange or route-server operator, ASPA in rustbgpd today
means:

- **No new infrastructure.** ASPA records arrive over the RTR caches
  already configured for RPKI origin validation, when a cache speaks
  RTR v2. There is no separate ASPA configuration.
- **Verification with the draft's applicability bounds.** Role-aware
  upstream/downstream verification on eBGP IPv4/IPv6-unicast ingress,
  with the first-AS precondition, local RS-client-role exemption,
  and iBGP exclusion described above.
- **Operator-controlled enforcement.** Deploy in observation first:
  ASPA states are visible per route over gRPC and the CLI, in
  telemetry (`bgp_aspa_records`,
  `bgp_validation_import_refreshes_total`), and in the
  looking-glass filtered view via reject-reason detail. Tag with
  communities or shift preference through policy next, and move to
  `match_aspa_validation = "invalid"` deny once ASPA object coverage
  among your members is understood. Verdicts track cache updates
  automatically in every mode.
- **An honest §5.6 boundary.** Default rejection enforcement and the
  retention contract behind it are explicitly not shipped; the go /
  no-go gates for activating them are recorded in
  [ADR-0123](adr/0123-aspa-v27-mitigation-and-retention.md).

Related material: the [IXP evaluation matrix](ixp-evaluation.md), the
[daemon comparison](COMPARISON.md), and the
[route-server cookbook](cookbook/route-server.md).
