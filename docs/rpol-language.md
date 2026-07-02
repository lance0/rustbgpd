# The rustbgpd policy language (`.rpol`) — reference draft

Status: **draft** (ADR-0096 slice 2). The frontend — lexer, parser,
typechecker, in-language tests, and `rbgp policy check` — is complete;
daemon integration (referencing `.rpol` policies from configuration,
`rbgp policy test --rib live`) ships in a later slice. Nothing in this
document is wired into a running daemon yet.

`.rpol` compiles to the same public typed IR (`rustbgpd_policy::ir`)
that TOML policy chains compile to, and is evaluated by the same
tree-walk engine. Match data (prefix sets, community sets, AS-path
regexes) compiles out of the program into shared indexed structures —
a thousand-member set costs one hash probe per route, not a
thousand-statement walk.

## Example

```rpol
# Sets: match data, compiled to indexed structures.
prefix-set customers { 10.10.0.0/16 ge 24 le 28, 192.0.2.0/24 }
community-set tagged { 65000:100, 65000:200 }

# A predicate policy: matches bogons, rejects everything else.
policy bogon-filter {
    term bogons { if route.prefix == 0.0.0.0/8 { accept } }
    term everything-else { reject }
}

# A parameterized policy: `peer_lp` is substituted at instantiation.
policy customer-in(peer_lp: u32) {
    term rpki-guard {
        if route.rpki == invalid { reject }
    }
    term customer-routes {
        if route.prefix in customers && route.communities has 65000:100 {
            set local-pref peer_lp;
            add community 65001:999;
            accept
        }
    }
    term bogon-guard { if apply(bogon-filter) { reject } }
}

# In-language tests, run by `rbgp policy check`.
test customer-in-accepts-tagged {
    route { prefix 10.10.1.0/24; communities [65000:100]; rpki valid }
    expect customer-in(200) == accept with local-pref 200
}
```

```console
$ rbgp policy check customer-in.rpol
customer-in.rpol: 1 passed, 0 failed
$ echo $?
0
```

Exit codes: `0` clean, `1` compile diagnostics (or unreadable file),
`2` in-language test failures. `--json` emits a machine-readable
report.

## Lexical structure

- **Comments**: `#` to end of line.
- **Identifiers** (set, policy, term, test, parameter names) are
  kebab-case: `[A-Za-z_][A-Za-z0-9_]*(-[A-Za-z0-9_]+)*`. There is no
  arithmetic in the language, so `-` inside names is unambiguous.
- **Reserved keywords** (not usable as names): `prefix-set`,
  `community-set`, `policy`, `term`, `test`, `if`, `else`, `set`,
  `add`, `remove`, `prepend`, `accept`, `reject`, `apply`, `in`,
  `has`, `matches`, `contains`, `ge`, `le`, `route`, `peer`,
  `expect`, `with`, `as`, `self`, `u32`. Field names (`local-pref`,
  `communities`, …) and enum members (`valid`, `internal`, …) are
  contextual, not reserved.
- **Literals** are single tokens, longest-match:
  - Prefix: `10.0.0.0/8`, `2001:db8::/32`. Host bits set beyond the
    prefix length are a compile error (not silently masked). IPv6
    literals must use the compressed `::` form — all-numeric
    full-form IPv6 is ambiguous with community literals.
  - IP address: `192.0.2.1`, `2001:db8::1`.
  - Standard community: `65000:100` (both parts u16), or a well-known
    name: `NO_EXPORT`, `NO_ADVERTISE`, `NO_EXPORT_SUBCONFED`,
    `BLACKHOLE`, `GRACEFUL_SHUTDOWN`.
  - Large community: `65000:1:2` (three u32), also accepted as
    `LC:65000:1:2` for parity with the TOML frontend.
  - Extended community (Route Target / Route Origin):
    `RT:65001:100`, `RO:65001:100`, `RT:192.0.2.1:5` (IPv4 admin),
    `RT:200000:100` (4-octet-AS admin). IPv4 and 4-octet-AS admins
    take a u16 local part (RFC 4360 encodings).
  - Strings (AS-path regexes, peer-group names): `"..."` with `\"`
    and `\\` escapes.
- **Statement separators**: `;` between statements is conventional
  but optional (the grammar is unambiguous without it); the idiomatic
  style semicolon-terminates everything except a final verdict.

## Types

The type universe is fixed; there are no user-defined types, maps, or
loops (ADR-0096 Decision 2/4), and inference is trivial: every field
has a known type and every operator a fixed signature.

| Type | Values | Where |
|---|---|---|
| bool | guard expressions | `if` conditions |
| u32 | integer literals, parameters | `local-pref`, `med`, `as-path.len`, `peer.asn`, arguments |
| prefix | prefix literals | `route.prefix` |
| community (3 kinds) | community literals | community lists, sets, actions |
| as-path | — (matched, never named) | `route.as-path` |
| rpki-state | `valid`, `invalid`, `not-found` | `route.rpki` |
| aspa-state | `valid`, `invalid`, `unknown` | `route.aspa` |
| route-type | `local`, `internal`, `external` | `route.route-type` |
| IP address | address literals | `route.next-hop`, `peer.address` |
| string | string literals | regexes, `peer.group` |

## Sets

```rpol
prefix-set NAME { PREFIX [ge N] [le N], ... }
community-set NAME { COMMUNITY-LITERAL, ... }
```

- `ge`/`le` bounds are per member, with the same semantics as the
  TOML frontend (and Cisco/Juniper prefix lists): the candidate is
  masked at the member's length and its length must fall in the
  derived range (`ge` only → `ge..=address_bits`; `le` only →
  `member_len..=le`; neither → exact length).
- Community sets may mix standard, large, and extended members.
  Membership (`in`) matches when **any route community of any kind
  matches any member** — the set is kind-partitioned internally, and
  the field you write it against (`route.communities in tagged`)
  reads as documentation, not a kind filter.
- Sets are content-interned: identical sets (in any member order)
  share one indexed structure across all policies.
- There is no `as-path-set` in V1 — inline
  `route.as-path matches "regex"` covers the need (deliberately
  deferred; the regex engine is the existing Cisco-style matcher).

## Policies, terms, and evaluation order

```rpol
policy NAME[(param: u32, ...)] {
    term NAME { statement... }
    ...
}
```

- Terms evaluate in order. Statements inside a term are: bare actions,
  or `if <expr> { actions... } [else { actions... }]`. `if` bodies are
  flat action lists — **no nested `if`** in V1 (split the condition
  with `&&` or use another term).
- **Verdicts**: `accept` permits the route (with all modifications
  executed so far in this policy); `reject` denies it (a denied route
  has no attributes — modifications in a rejecting branch are
  discarded). A verdict ends the policy's evaluation.
- **Fallthrough**: if a guard doesn't match, or a matched body ends
  without a verdict, evaluation continues to the next term.
  Modifications executed along the way (Junos-style
  modify-and-continue) are kept and merged into the eventual accept.
- **End of policy without a verdict = accept** (with any accumulated
  modifications). In chain terms: the policy raises no objection and
  the chain continues — this matches the GoBGP-style chain semantics
  the daemon already uses (each policy's permit accumulates and
  continues; a deny terminates the chain).
- Statements after a bare `accept`/`reject` in the same term (or
  actions after a verdict in the same `if` body) are **unreachable
  and a compile error**.

### Lowering into the IR (normative)

The IR's `Term` is one `(guard, action)` pair; an `.rpol` term lowers
to one or more IR terms:

- Each `if` becomes an IR term (guard = condition); its `else`
  becomes a following IR term guarded by the negated condition.
- A run of bare modification actions flushes as an unconditional
  `Continue` IR term (a small IR addition made for this frontend:
  guard matched → apply modifications → keep walking this policy's
  terms).
- When one `.rpol` term produces multiple IR terms they are named
  `<term>.<n>` (1-based); a lone IR term keeps the plain term name.
  Explain surfaces will render these names.

### Parameters

Parameters are `u32` only in V1 and can appear anywhere a u32 is
expected (`set local-pref peer_lp`, `route.local-pref >= peer_lp`,
`apply(p(peer_lp))`, `route.as-path contains asn_param`). A
parameterized policy is a **template**: each use site with concrete
arguments is monomorphized at compile time (clone-with-substitution;
policies are small, this is microseconds). The evaluator only ever
sees constants. The `prepend` count must be a literal (1–255, it is
wire-encoded as u8).

## Expressions

Boolean operators, loosest to tightest: `||`, `&&`, `!`. Parentheses
group. Comparisons: `==`, `!=`, `>=`, `<=`.

| Predicate | Meaning |
|---|---|
| `route.prefix == 10.0.0.0/24` | exact prefix (same network *and* length) |
| `route.prefix in customers` | prefix-set membership (mask + ge/le ranges) |
| `route.communities has 65000:100` | route carries this community (kind-checked against the field) |
| `route.communities in tagged` | any route community matches any set member |
| `route.as-path.len >= 3` | AS-path ASN count (RFC 4271 counting) |
| `route.as-path contains 65001` | boundary-anchored ASN presence (sugar for `matches "_65001_"`) |
| `route.as-path matches "^65010"` | Cisco/Quagga-style regex; `_` is a boundary anchor |
| `route.local-pref >= 200`, `route.med <= 50` | u32 comparisons; `==`/`!=` also allowed |
| `route.next-hop == 10.0.0.1` | next-hop equality (`==`/`!=` only) |
| `route.rpki == invalid` | RPKI origin validation state |
| `route.aspa == unknown` | ASPA verification state |
| `route.route-type == external` | route source class |
| `route.evpn-route-type == 2` | EVPN route type (integer literal 0–255; `==`/`!=` only) |
| `peer.address == 192.0.2.1` | evaluation-peer address |
| `peer.asn == 65010` | evaluation-peer ASN (`==`/`!=` only) |
| `peer.group == "leaf"` | evaluation-peer group name |
| `apply(other-policy)` / `apply(p(42))` | policy-as-predicate (below) |

**Implicit defaults** (identical to the TOML engine and RFC 4271):
comparisons against `route.local-pref` see **100** when the attribute
is absent, `route.med` sees **0**. Prefix predicates never match a
prefixless route (e.g. BGP-LS NLRIs); `route.next-hop`,
`route.route-type`, and `route.evpn-route-type` never match when the
corresponding attribute is absent.

`==` on u32 fields lowers to `>= v && <= v`; `!=` is its negation.

### `apply` — policy as predicate

`apply(p)` is a **boolean**: "would policy `p` permit this route?".
The applied policy's actions do *not* execute — this is a predicate,
not a Junos-style subroutine call with side effects. The compiler
inlines `p`'s first-match decision structure as a pure guard
expression; `Continue`-style modify-and-fallthrough terms in `p`
don't decide anything and are skipped.

Two consequences worth internalizing:

- Policy composition must form a **DAG** — recursion through `apply`
  (including self-application) is a compile error naming the cycle.
- Since end-of-policy defaults to accept, a policy that never
  `reject`s is constant-true under `apply`. Predicate policies should
  decide both ways (see `bogon-filter` above: match → `accept`,
  final term → `reject`).

## Actions

| Action | Effect |
|---|---|
| `accept` / `reject` | terminal verdict (see evaluation order) |
| `set local-pref <u32>` | override `LOCAL_PREF` |
| `set med <u32>` | override `MED` |
| `set next-hop <ip>` / `set next-hop self` | override `NEXT_HOP` |
| `add community 65001:999` / `remove community ...` | standard communities |
| `add large-community 65000:1:2` / `remove ...` | large communities |
| `add ext-community RT:65001:100` / `remove ...` | extended communities (RT/RO) |
| `prepend as <asn> <count>` | prepend `<count>` copies of `<asn>` (count: literal 1–255) |

The kind keyword must match the literal's kind (`add community
RT:...` is a compile error pointing at `add ext-community`). Within a
policy, later `set`s of the same attribute win; across a chain, the
existing merge semantics apply (later policy wins scalars, add/remove
lists merge with later-policy-wins cancellation).

Extended-community wire encoding follows the daemon's other
frontends: dotted-quad admin → RFC 4360 type 0x01, ASN > 65535 →
type 0x02, otherwise type 0x00 (subtype 0x02 RT / 0x03 RO).

## Tests

```rpol
test NAME {
    route { FIELD VALUE; ... }
    [peer { address IP; asn N; group "NAME" }]
    expect POLICY[(args)] == accept|reject [with ASSERTION, ...]
    [expect ...]
}
```

Route fixture fields: `prefix`, `communities [..]`,
`large-communities [..]`, `ext-communities [..]`, `as-path "65001
65002"`, `next-hop`, `local-pref`, `med`, `rpki`, `aspa`,
`route-type`, `evpn-route-type`. Omitted fields are absent attributes
(so `local-pref`/`med` comparisons see the implicit 100/0, `rpki`
defaults to `not-found`, `aspa` to `unknown`). The fixture AS-path
length is the whitespace-word count of the string form.

`with` assertions check the evaluation result's **modifications**
(the frontend has no live route to apply them to): `local-pref N`,
`med N`, `next-hop IP|self`, `community LIT` (and
`large-community`/`ext-community`, asserting presence in the add
lists), `prepend as ASN COUNT`.

Tests run at check time (`rbgp policy check`, CI) with zero daemon
involvement. Testing a *candidate* policy against a live RIB
(`rbgp policy test --rib live`) is the later ADR-0096 slice.

## Grammar sketch

```text
file        := (prefix-set-def | community-set-def | policy-def | test-def)*
prefix-set-def    := "prefix-set" IDENT "{" [prefix-entry ("," prefix-entry)*] "}"
prefix-entry      := PREFIX ["ge" INT] ["le" INT]
community-set-def := "community-set" IDENT "{" [community ("," community)*] "}"
policy-def  := "policy" IDENT ["(" param ("," param)* ")"] "{" term* "}"
param       := IDENT ":" "u32"
term        := "term" IDENT "{" stmt* "}"
stmt        := if-stmt | action [";"]
if-stmt     := "if" expr "{" (action [";"])* "}" ["else" "{" (action [";"])* "}"]
action      := "accept" | "reject"
             | "set" ("local-pref" | "med") u32arg
             | "set" "next-hop" (IP | "self")
             | ("add" | "remove") ("community" | "large-community" | "ext-community") community
             | "prepend" "as" u32arg INT
expr        := and ("||" and)*
and         := unary ("&&" unary)*
unary       := "!" unary | "(" expr ")" | "apply" "(" IDENT ["(" u32arg,* ")"] ")" | predicate
predicate   := field (("=="|"!="|">="|"<=") rhs | "in" IDENT | "has" community
             | "matches" STRING | "contains" u32arg)
field       := ("route" | "peer") ("." IDENT)+
u32arg      := INT | IDENT          # parameter reference
test-def    := "test" IDENT "{" route-block [peer-block] expect+ "}"
expect      := "expect" IDENT ["(" INT,* ")"] "==" ("accept"|"reject") ["with" assertion,*]
```

## Diagnostics

Every error carries labeled source spans (ariadne rendering), and the
compiler recovers to report multiple independent errors per file.
Unknown names (sets, policies, fields, enum members, parameters, test
fixture fields) get did-you-mean suggestions by edit distance;
kind/type mismatches say what to write instead.

```text
Error: unknown prefix-set `custmers`
   ╭─[ broken.rpol:5:28 ]
   │
 5 │         if route.prefix in custmers && route.rpki == vaild { reject }
   │                            ────┬───
   │                                ╰───── no prefix-set with this name
   │
   │ Note: did you mean `customers`?
───╯
```

## Deliberate V1 exclusions

No loops, no user-defined types, no maps (safety is total by
construction — ADR-0096 Decision 2). No `as-path-set`. No `else if`
chains and no nested `if` (keep terms small; use `&&` or more terms).
No arithmetic. EVPN route type takes only an integer literal (no
parameters — the value is wire-encoded u8). Full-form all-numeric
IPv6 literals (use `::` compression). These are scope decisions, not
parser accidents; each has an error message steering to the
supported form.
