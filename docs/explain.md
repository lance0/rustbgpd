# Explaining routes: "why is this route (not) here?"

Every stage of a route's life through the daemon can explain itself,
from the live RIB, in one command — no debug rebuild, no external
looking-glass daemon, no packet capture. This page is the catalog:
which question you have, which command answers it, and what the answer
looks like. Deep semantics live in
[OPERATIONS.md](OPERATIONS.md); this page gets you to the right
command.

Every command below also takes `--json` for scripting and portal
backends.

| Question | Command |
|----------|---------|
| Why was this path selected as best? | `rbgp rib --prefix <cidr> --explain` |
| Why did/didn't this prefix go to that peer? | `rbgp rib --prefix <cidr> advertised <peer> --explain` |
| What did import policy decide for this prefix from that peer? | `rbgp policy explain --neighbor <peer> --prefix <cidr>` |
| Which of a member's routes were filtered, and why? | `rbgp rib received <peer> --rejected` |
| What would this candidate policy do to the live RIB? | `rbgp policy test <file> --policy <name> --direction import` |
| Which policy terms are actually firing? | `rbgp policy stats` |
| What would this config change touch? | `rbgp config diff <candidate.toml>` |

For operators coming from FRR/BIRD, the
[familiar command map](../crates/cli/README.md#familiar-command-map)
translates the usual show-commands into these.

## Best-path explain — decisive-comparison attribution

Why did this path win? Every losing candidate is annotated with the
decisive comparison step (`only_path`, `higher_local_pref`,
`shorter_as_path`, `lower_origin`, `lower_med`, ... down to
`lower_peer_address`) and the compared values behind it, plus its
equal-cost multipath classification:

```console
$ rbgp rib --prefix 203.0.113.0/24 --explain
Best-path explanation for 203.0.113.0/24
Best route: peer=10.0.0.2, next_hop=10.0.0.2, as_path=[65002]
Selected:   only path for this prefix
No candidates
```

With competing paths, the candidate table lists each loser with its
`Reason` / `Detail` (e.g. `local_pref 100 < 200`) and multipath
eligibility. `--json` returns the same as `best_reason`,
`best_reason_detail`, and a `candidates[]` array.

Scope the explanation to one peer's Add-Path send view with
`--explain-peer <addr>`: candidates the peer would actually receive
get their advertised rank; filtered ones show why they are not sent.
Details: [OPERATIONS.md](OPERATIONS.md#explain-a-best-path-decision).

## Export explain — the full gate ladder, from the real export body

Why did (or didn't) this exact prefix reach this exact peer? The
answer is produced by a read-only dry run of the *same staging body*
live distribution executes — update groups, split horizon per member,
and all — so it cannot drift from what the wire does:

```console
$ rbgp rib --prefix 203.0.113.0/24 advertised 10.0.0.2 --explain
Advertise: 203.0.113.0/24 to 10.0.0.2
Update group: 3 (shared staging; split horizon applied per member)
Gate ladder (live evaluation order):
  [pass] best_route       Loc-RIB best exists
  [pass] split_horizon    not the source peer
  [pass] rr_reflection    eBGP peer
  [pass] family           ipv4-unicast negotiated
  [pass] llgr             no stale restriction
  [pass] orf              no peer filter installed
  [pass] export_policy    ix-egress:announce-members permit
  [pass] adj_rib_out      staged_announce
```

(Values above are illustrative; the rung set and order are the live
ones.) A denial shows `[STOP]` at the gate that held the route back,
with per-term policy attribution for `.rpol` chains. `--rd <rd>`
explains the VPNv4/VPNv6 (RD, prefix) ladder including the RFC 4684
RT-Constrain membership gate; `--labeled` explains the RFC 8277
labeled-unicast ladder. Rung-by-rung semantics:
[OPERATIONS.md](OPERATIONS.md#explain-an-export-decision-why-diddidnt-route-x-go-to-peer-y).

For a negotiated unicast Add-Path send peer, add the paired
`--source-peer <addr> --source-path-id <id>` flags to answer the same question
for one exact Adj-RIB-In candidate (including inbound ID 0). The source
identity is echoed separately from the outbound `path_id`: RFC 7911 requires
the re-advertiser to assign its own ID, so the latter is the compact eligible,
policy-permitted rank. It stays 0 before ranking or beyond `send_max`; an OTC
or exact-wire denial after ranking retains the attempted rank. Omit the flags
for the legacy winner-oriented explanation.

## Import explain — the per-session decision cache

What did import policy decide when this prefix arrived from this
peer — including paths that were denied and are therefore *not in the
RIB anymore*? Requires `[policy.explain] enabled = true` on the
daemon (a bounded per-session decision cache):

```console
$ rbgp policy explain --neighbor 10.0.0.2 --prefix 10.10.1.0/24
import policy explain — peer 10.0.0.2 prefix 10.10.1.0/24 (policy generation 3)
  permit
    policy:  customer-in(200)
    statements:
      [0] policy customer-in(200) term customer-routes permit  match: guard route.prefix in customers  set: local_pref 100 -> 200
        term rpki-guard: route.rpki == invalid => reject [not matched]
        term customer-routes: route.prefix in customers => set local-pref 200; accept [matched]
```

Outcomes are `permit` / `deny` / `withdrawn` / `not_seen` / `evicted`
/ `stale`; a disabled cache or missing session errors distinctly
instead of pretending `not_seen`. `--path-id` narrows to one Add-Path
identity. Details:
[OPERATIONS.md](OPERATIONS.md#explain-an-import-decision-adr-0073).

## The filtered-route view — rejected routes, retained with reasons

The route-server member-support question — "you're eating my
routes, which ones and why?" — without knowing a prefix in advance.
The daemon retains rejected inbound routes per session
(`[policy.reject_retention]`, bounded LRU) with a canonical reason
token:

```console
$ rbgp rib received 198.51.100.2 --rejected
Prefix                 PathId   Reason             Detail                       Next Hop           RPKI       AS Path
------------------------------------------------------------------------------------------------------------------------
203.0.113.0/24         0        policy_reject      member-import                198.51.100.2       invalid    64500 64501
```

Reason tokens: `policy_reject`, `otc_route_leak`,
`next_hop_ownership`, `as_path_loop`, `rr_loop`,
`treat_as_withdraw`. The same rows back a looking glass via the
[birdwatcher adapter](../examples/birdwatcher-adapter/README.md),
which maps each token to an Alice-LG-matchable large community. The
member-support workflow around this view is in the
[route-server cookbook](cookbook/route-server.md#member-support-the-filtered-route-view).

## The support-ticket workflow

"Member AS64500 says their prefix isn't visible." In order:

<!-- rbgp-cli-conformance -->
```bash
# 1. Is the session even up, and are we retaining anything from them?
rbgp summary
rbgp rib received 198.51.100.2 --rejected

# 2. Rejected with a reason token? Get the statement-level why.
rbgp policy explain --neighbor 198.51.100.2 --prefix 203.0.113.0/24

# 3. Accepted but another member doesn't see it? Walk the export ladder
#    toward that member.
rbgp rib --prefix 203.0.113.0/24 advertised 198.51.100.7 --explain

# 4. Accepted but lost best-path selection? See what beat it.
rbgp rib --prefix 203.0.113.0/24 --explain
```

Each step either answers the ticket or names the exact gate, term, or
comparison to look at next.

## Related introspection surfaces

| Surface | What it answers |
|---------|-----------------|
| `rbgp policy test <file> --policy <p> --direction <d>` | Read-only dry run of a *candidate* policy against the live RIB: accepted/rejected/modified counts, term hits, per-attribute before/after diffs ([rpol-language.md](rpol-language.md)) |
| `rbgp policy check <file>` | Offline parse/typecheck plus the file's in-language `test` blocks — no daemon needed |
| `rbgp policy stats` (alias `counters`) | Live per-term hit counters: which policy terms actually fire |
| `rbgp config diff <candidate>` / `rbgp config plan` | What a config change would touch, each field annotated hot-applied / session reset / restart required ([OPERATIONS.md](OPERATIONS.md#config-diff-dry-run-reload)) |
| `rbgp diff advertised --against <snapshot>` | Live Adj-RIB-Out vs a recorded snapshot — the shadow-cutover gate ([ribdiff.md](ribdiff.md)) |
| `rbgp doctor` | Red/green triage checks plus a redacted support bundle ([OPERATIONS.md](OPERATIONS.md#support-bundles-and-triage-checks-rbgp-doctor)) |
