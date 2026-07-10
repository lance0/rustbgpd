# The rustbgpd policy language (`.rpol`) — reference

Status: **shipped** (ADR-0096, complete). The frontend — lexer,
parser, typechecker, in-language tests, and `rbgp policy check` — the
daemon integration — `[policy] rpol_files` config references, mixed
TOML/rpol chains, SIGHUP hot-apply, and the `rbgp policy test`
live-RIB dry run — and the explain surfaces — per-term statement
traces in `rbgp policy explain` / `rbgp rib advertised --explain` and
live per-term hit counters via `rbgp policy stats` — are all live
(see "Using policies in the daemon" below). The M80 interop lab
proves route-for-route parity against FRR route-maps expressing the
same intent, plus `.rpol`-edit-under-traffic hot-apply with Route
Refresh scoped to the peers whose chains changed.

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
  kebab-case: `[A-Za-z_][A-Za-z0-9_]*(-[A-Za-z0-9_]+)*`. Maximal munch
  is permanent (ADR-0103): `a-b` is always one identifier, so binary
  subtraction requires whitespace — `route.med - 1` subtracts,
  `route.med-1` is an unknown-field error (with a did-you-mean note).
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
    take a u16 local part (RFC 4360 encodings). Well-known names:
    `OV_VALID`, `OV_NOT_FOUND`, `OV_INVALID` — the RFC 8097
    origin-validation states (non-transitive opaque, type `0x43`
    sub-type `0x00`, state in the last octet), matched and
    added/removed by exact wire value.
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
| u32 | integer literals, parameters, `let` bindings | `local-pref`, `med`, `as-path.len`, `origin-as`, `peer.asn`, arguments; the only arithmetic type — all arithmetic is **checked** (overflow/underflow/division-by-zero are evaluation errors, never wraps or traps) |
| prefix | prefix literals | `route.prefix` |
| community (3 kinds) | community literals | community lists, sets, actions |
| as-path | — (matched, never named) | `route.as-path` |
| rpki-state | `valid`, `invalid`, `not-found` | `route.rpki` |
| aspa-state | `valid`, `invalid`, `unknown` | `route.aspa` |
| route-type | `local`, `internal`, `external` | `route.route-type` |
| route-family | `ipv4-unicast`, `ipv6-unicast`, `ipv4-labeled-unicast`, `ipv6-labeled-unicast`, `vpnv4`, `vpnv6`, `ipv4-flowspec`, `ipv6-flowspec`, `evpn`, `rtc`, `bgp-ls`, `bgp-ls-vpn` | `route.family` |
| IP address | address literals | `route.next-hop`, `peer.address` |
| string | string literals | regexes, `peer.group` |

## Sets

```rpol
prefix-set NAME { PREFIX [ge N] [le N], ... }
community-set NAME { COMMUNITY-LITERAL, ... }
asn-set NAME { ASN, ... }
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
- ASN sets hold plain ASN literals (u32; 4-byte ASNs are first-class,
  out-of-range literals are a compile error, duplicates deduplicate).
  Membership is probed by `route.origin-as in NAME` and
  `peer.asn in NAME` — one hash probe regardless of set size. Like
  strict next-hop, this is an `.rpol`-only surface: the TOML frontend
  has no equivalent.
- Sets are content-interned: identical sets (in any member order)
  share one indexed structure across all policies.
- There is no `as-path-set` in V1 — inline
  `route.as-path matches "regex"` covers the need (deliberately
  deferred; the regex engine is the existing Cisco-style matcher).

Migrating an origin lock from an AS-path regex to an ASN set:

```rpol
# Before: one regex alternation, re-matched against the rendered
# AS-path string per evaluation.
policy customer-origins-old {
    term match { if route.as-path matches "_(64500|64501|64502)$" { accept } }
    term rest { reject }
}

# After: one indexed set, one O(1) probe against the typed origin;
# reusable across policies, no regex escape gymnastics for new ASNs.
asn-set customers { 64500, 64501, 64502 }

policy customer-origins {
    term match { if route.origin-as in customers { accept } }
    term rest { reject }
}
```

## Policies, terms, and evaluation order

```rpol
policy NAME[(param: u32, ...)] {
    term NAME { statement... }
    ...
}
```

- Terms evaluate in order. Statements inside a term are: bare
  actions, `let` bindings (see "Bindings"), or `if <expr> {
  actions... } [else { actions... }]`. `if` bodies are flat
  action/`let` lists — **no nested `if`** in V1 (split the condition
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
- Each `let` becomes a `Bind` IR term (LAN-302): guard = the
  enclosing branch condition (`True` in term-body position; the `if`
  guard — or its negation for `else` — for a body binding), action =
  evaluate the initializer and write its frame slot. Like `Continue`
  it never decides; body bindings re-evaluate the branch guard, which
  is pure and cannot diverge.
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
| `route.origin-as == 64500` | origin AS — the last ASN of the rightmost non-empty `AS_SEQUENCE` (`==`/`!=` only) |
| `route.origin-as in customers` | asn-set membership (one hash probe) |
| `peer.asn in customers` | evaluation-peer ASN against the same asn-sets |
| `route.local-pref >= 200`, `route.med <= 50` | u32 comparisons; `==`/`!=` also allowed |
| `route.med + 50 >= threshold`, `route.as-path.len * 10 >= route.med` | checked-arithmetic comparison (see "Value expressions"); an unresolvable operand **denies** the route |
| `route.next-hop == 10.0.0.1` | next-hop equality (`==`/`!=` only) |
| `route.next-hop == peer.address` | strict next-hop — the one field-vs-field comparison; reads peer identity, so an export chain using it makes the peer ineligible for update-group sharing (`policy_peer_context`) |
| `route.rpki == invalid` | RPKI origin validation state |
| `route.aspa == unknown` | ASPA verification state |
| `route.route-type == external` | route source class |
| `route.evpn-route-type == 2` | EVPN route type (integer literal 1–5, RFC 7432 §7; `==`/`!=` only) |
| `route.family == ipv4-unicast` | typed AFI/SAFI route family (`==`/`!=` only); route-context-only, so it never disqualifies update-group sharing |
| `peer.address == 192.0.2.1` | evaluation-peer address |
| `peer.asn == 65010` | evaluation-peer ASN (`==`/`!=` only) |
| `peer.group == "leaf"` | evaluation-peer group name |
| `apply(other-policy)` / `apply(p(42))` | policy-as-predicate (below) |

**Implicit defaults** (identical to the TOML engine and RFC 4271):
comparisons against `route.local-pref` see **100** when the attribute
is absent, `route.med` sees **0**. Prefix predicates never match a
prefixless route (e.g. BGP-LS NLRIs); `route.next-hop`,
`route.route-type`, `route.evpn-route-type`, and `route.family` never
match when the corresponding attribute is absent. `route.origin-as` is
absent on empty and `AS_SET`-only paths and then matches neither `==`
nor `!=` nor `in` (`!(... in ...)` negates plainly, matching the
prefix-set precedent).

`==` on u32 fields lowers to `>= v && <= v`; `!=` is its negation.

### Value expressions — checked u32 arithmetic

u32 value positions — either side of a u32 comparison, and the
`set local-pref` / `set med` arguments — accept **value expressions**
(ADR-0103, LAN-299): arithmetic over integer literals, parameters,
`let` bindings (below), u32-typed fields (`route.local-pref`,
`route.med`, `route.as-path.len`, `route.origin-as`, `peer.asn`), and
three bounded builtins. A comparison's left side may also carry
arithmetic when it starts with a field or a binding.

```rpol
set med route.med + 50
set local-pref min(route.local-pref * 2, 400)
if route.as-path.len * 10 >= route.med { reject }
if route.med >= threshold + 20 { set local-pref 90 }
```

- **Operators**: `+ - * / %`, with `* / %` binding tighter than
  `+ -`, and both tighter than comparisons. Parentheses group inside
  value positions (a `(` at the *start* of an `if` condition opens a
  boolean group, so lead with the field: `route.med + 2 * 3 >= n`,
  or put the parenthesized arithmetic on the right).
- **Whitespace disambiguates `-`**: identifiers are kebab-case with
  permanent maximal munch, so `route.med - 1` is subtraction and
  `route.med-1` is an unknown-field error.
- **Builtins**: `min(a, b)`, `max(a, b)`, `clamp(x, lo, hi)`.
  Statically inverted clamp bounds (`lo > hi` with both constant) are
  a compile error; a data-dependent inversion is an evaluation error.
- **Everything is checked.** All arithmetic is checked u32: overflow,
  underflow, and division/modulo by zero are **evaluation errors**,
  never wraps or process traps.
- **Constant folding.** Constant subexpressions fold at compile time
  with the same checked operators: `set med 25 + 25` compiles to
  exactly what `set med 50` does, and a statically invalid constant
  expression (`4294967295 + 1`, `1 / 0`) is a compile error at its
  source span.

**Failure is closed (the evaluation-error contract).** Any evaluation
error — checked-arithmetic failure, inverted clamp, or an **absent
operand** (`route.origin-as` on an empty/`AS_SET`-only path, unknown
`peer.asn`) — denies the route: staged modifications are discarded,
the chain's eval-error counter increments, a rate-limited WARN names
the failing policy and term, and explain traces render the error in
place of a verdict. `route.local-pref` and `route.med` read their
implicit defaults (100 / 0) when absent, consistent with comparisons.
Note the deliberate divergence from plain comparisons: an
arithmetic-free `route.origin-as == 64500` on an origin-less route
matches neither `==` nor `!=` (never-match), while
`route.origin-as * 1 == 64500` is unresolvable and **denies** — the
computed form has no non-verdict to fall back to, exactly like
computed prepend operands.

**Update-group note.** `peer.asn` as an operand (guard or computed
`set` value) reads peer identity and keeps its peers out of shared
update groups; arithmetic over route fields alone never disqualifies
grouping.

Migration example — BIRD's arithmetic filters are the natural
comparison. A BIRD MED-dampening filter:

```text
filter pad_med {
    if bgp_med + 50 > 1000 then reject;
    bgp_med = bgp_med + 50;
    bgp_local_pref = bgp_local_pref * 2;
    accept;
}
```

becomes:

```rpol
policy pad-med {
    term dampen { if route.med + 50 >= 1001 { reject } }
    term pad {
        set med route.med + 50;
        set local-pref min(route.local-pref * 2, 400);
        accept
    }
}
```

The difference under the syntax: BIRD's integer arithmetic evaluates
in a general-purpose interpreter, and an out-of-range result is
whatever the interpreter does that day; `.rpol` arithmetic is checked
u32 with a pinned failure contract (deny + counter + explain), and
the `min` cap makes the local-pref doubling total instead of relying
on it.

### Bindings — `let`

`let <name> = <value expression>` names a computed `u32` in statement
position — a term body, or an `if`/`else` body (ADR-0103, LAN-302):

```rpol
policy dampen {
    term score {
        let origin = route.origin-as
        let penalty = route.as-path.len * 10
        if penalty >= route.med { reject }
        if origin == 64500 { set med penalty; accept }
    }
    term rest { accept }
}
```

`let` is a contextual identifier, not a reserved word: statement
position admits no other bare identifier, so sets, policies, and
parameters named `let` keep working.

**Immutable, u32-only.** There is no assignment, no `var`, and no
mutation: a binding's value is fixed by its initializer for the rest
of its scope. Bindings hold `u32` values only this slice — the
initializer is a value expression, so the bindable inputs are integer
literals, parameters, other bindings, and the u32 fields
(`route.local-pref`, `route.med`, `route.as-path.len`,
`route.origin-as`, `peer.asn`); binding a non-u32 field is a compile
error naming the u32 field set.

**Scope and shadowing (normative).**

- A term body is a scope; each `if`/`else` body is a nested scope.
  A binding is visible from its statement to the end of its scope —
  a term-body binding reaches into later `if` bodies of the same
  term; a body binding is invisible outside its body. Bindings never
  cross terms, and never escape the policy (no globals, no
  cross-route state, no closures — the purity contract).
- A `let` may shadow an earlier binding, including one in the same
  scope, and a policy parameter: the **innermost declaration wins**
  at each use. The initializer is resolved *before* its own name is
  declared, so `let x = x + 1` reads the outer `x` — shadowing, never
  self-reference.
- Resolution is **position-typed**, the same rule that lets a
  parameter named `origin` keep its meaning under `prepend as`
  (LAN-296): bindings are readable only in value positions. Enum
  members (`valid`, `internal`, …) still win in enum comparisons,
  `min`/`max`/`clamp` followed by `(` are still builtin calls, and
  `prepend as origin` still means the origin operand even with a
  `let origin` in scope. Compile-time-constant positions (`apply`
  arguments, prepend operands/counts, `contains`) reject bindings
  with a dedicated diagnostic — they are runtime values.
- **Use before definition is a compile error** at the use's span, as
  is any unknown name (with did-you-mean suggestions over parameters
  and visible bindings).

**Evaluation is eager and fail-closed.** The initializer evaluates
when its statement executes — reached in the term walk, branch taken —
whether or not the value is ever read. It rides the same rails as all
checked arithmetic (LAN-299): overflow, underflow, division/modulo by
zero, or an absent operand (`route.origin-as` on an origin-less route,
unknown `peer.asn`) **denies the route** — staged modifications are
discarded, the eval-error counter increments, explain renders the
error in place of a verdict. A statement position the walk never
reaches (an earlier verdict decided, the branch not taken) never
evaluates. A binding whose comparison uses a plain u32 field
(`route.origin-as == x`) makes that comparison a *value* comparison:
fail-closed on absent operands, unlike the never-match plain form.

**Reads see the original route — never staged writes.** Route
mutation stays transactional: `set`/`add`/`remove`/`prepend` stage
modifications applied only after a complete successful evaluation, so
`set med 500` followed by `let x = route.med` binds the route's MED
*as it arrived*, not 500. Read-back of staged writes is deliberately
out of scope (it would break the memoization contract — `ExportMemo`
keys on source attributes plus modifications — and needs its own ADR
if ever demanded).

**Static slots, zero allocation.** Bindings compile to fixed slots in
a 256-slot register file (term, nested loop, and `if` scopes at the
64-binding per-scope cap; inlined function calls draw on the same
frame, LAN-304): slot assignment is a pure function of the source
(identical source → identical compiled form, so unchanged reloads
still diff as no-ops), sibling scopes reuse slots, and the frame is a
lazily-materialized stack array — policies without bindings pay
nothing, and no evaluation ever heap-allocates for bindings. The
**65th `let` in one scope is a compile error** at its span. The cost
DP charges each binding its initializer cost plus one slot step; each
read costs one step, so factoring a repeated subexpression through a
`let` is never more expensive than inlining it (and evaluates
identically — pinned by test).

**`apply` restriction.** A policy that declares `let` bindings cannot
be a target of `apply` this slice: `apply` inlines its target as a
pure predicate expression, which has no term walk to execute bindings
in. The compile error points at the offending `apply` and the target's
first `let`; factor the shared value into the applying policy, or use
a user function (`fn`, LAN-304) — the designed vehicle for composing
computed values.

Migration example — factoring a repeated computed value:

```rpol
# Before: the padded MED is computed twice and must be kept in sync.
policy pad-med-inline {
    term dampen { if route.med + 50 >= 1001 { reject } }
    term pad { set med route.med + 50; accept }
}

# After: one binding, one place to change the padding.
policy pad-med {
    term pad {
        let padded = route.med + 50
        if padded >= 1001 { reject }
        set med padded
        accept
    }
}
```

**Update-group note.** A binding whose initializer reads `peer.asn`
reads peer identity — even if the value is never used, an unknown
peer ASN already denies — so it keeps its peers out of shared update
groups, exactly like a `peer.asn` guard operand. Bindings over route
fields alone never disqualify grouping.

### Loops — `for`

`for <var> in <source> { ... }` walks a finite collection, binding
each element to an immutable `u32` loop variable — a fresh binding per
iteration, scoped to the body (ADR-0103 Decision 3, LAN-303):

```rpol
community-set scrub { 65000:100, 65000:200 }
asn-set bogon-asns { 64512, 65535 }

policy route-server-in {
    term scrub-communities {
        for c in route.communities {
            if c in scrub { remove community c }
        }
    }
    term bogon-path-guard {
        for asn in route.as-path {
            if asn in bogon-asns { reject }
        }
        accept
    }
}
```

`for`, `break`, and `continue` are contextual identifiers like `let`
(statement position admits no other bare identifier), so existing
names keep working. There is **no `while`** — every loop's source is
finite by construction, which is what keeps every bound provable or
runtime-meterable.

**Iteration sources — exactly three forms.**

- `route.communities` — the route's **standard** (RFC 1997)
  communities as raw `u32` values (`ASN << 16 | value`), in attribute
  order. This is the community-iteration decision for this slice: a
  standard community *is* a `u32`, so it rides the u32-only value
  model without a new type. `route.large-communities` and
  `route.ext-communities` do not iterate (their members are 96/64-bit
  — probe them with `has`/`in`); community-sets do not iterate either
  (mixed-kind members). A standard community literal doubles as a u32
  in value positions, so `if c == 65000:100 { ... }` reads naturally.
- `route.as-path` — every ASN in wire order: segments in order, ASNs
  within each segment in stored order, **prepend duplicates included**.
  `AS_SET` members are yielded individually in received order (note
  the asymmetry with `route.as-path.len`, which counts a whole set as
  1 per RFC 4271 §9.1.2.2). A route without an `AS_PATH` iterates zero
  times.
- A named `asn-set` — members in canonical order (sorted, deduplicated
  — the interned representation), so iteration order is deterministic
  across compiles and insertion orders. Sets larger than the 4,096
  per-loop bound are rejected at compile time (probe those with `in`).

**The loop variable in guards and actions.** It resolves like any
`let` binding: value comparisons and arithmetic, `in` membership —
against an `asn-set`, or against a `community-set`'s standard members
(`c in scrub` above; large/ext members of the set never match a u32)
— and the binding-valued community actions `add community <var>` /
`remove community <var>` (standard kind only), which stage the
element's value per execution: the scrub-loop idiom. Shadowing follows
the `let` rules — the loop variable shadows outer bindings, a body
`let` may shadow it.

**`break`, `continue`, verdicts.** `break` exits the innermost loop
(the walk continues after it); `continue` skips to the next iteration.
Staged modifications before either still apply — they are control, not
verdicts. `accept`/`reject` inside the body terminate the whole policy
at that iteration, exactly as in an `if` body; staged modifications
from earlier iterations merge under an `accept` and are discarded by a
`reject`, the ordinary rules.

**Iterated collections cannot change mid-loop.** Reads always see the
route as it arrived — staged modifications are never read back
(ADR-0103 Decision 2) — so `add community` inside a
`for c in route.communities` body cannot extend its own iteration
(pinned by test).

**Bounds and fuel (ADR-0103 Decision 3).** Every budget provable at
compile time is enforced at compile time, in the same cost DP that
bounds `apply`:

- **4,096 iterations per loop** (`MAX_LOOP_ITERATIONS`). Set sources
  are checked at compile time. Route-attribute sources are checked at
  runtime — a peer-supplied route with more elements than the cap
  (possible with RFC 8654 extended messages) is an **evaluation
  error** at the 4,097th element: uniform Deny, counter, rate-limited
  log — cap-then-error, never silent truncation.
- **Nesting ≤ 4 loops**, and the DP charges each loop at its static
  bound × per-iteration body cost — multiplicatively for nests — so a
  loop over one route attribute nested in a loop over another
  (4,096 × 4,096 steps) is rejected at compile time against the
  1,000,000-step worst-case budget (`MAX_EVAL_COST`), not metered per
  route. Nest small set loops, or restructure with membership probes.
- **Runtime fuel.** Every evaluation starts with `MAX_EVAL_COST` fuel,
  decremented **only at loop iteration steps** — straight-line code is
  pre-paid by the compile-time bound, so a chain with no loops pays
  exactly zero (fuel is one register write, never read again).
  Exhaustion — reachable only by compounding data-dependent iteration
  across a chain — is an evaluation error on the same uniform-Deny
  rail (`fuel-exhausted` in the error counters and explain traces).

**Explain.** Traces render a bounded loop summary — iteration count
plus the deciding iteration (`loop reject at iteration 3 of 3`), never
per-iteration lines. Hit counters count the loop's term once per walk;
body terms are inside the loop node and carry no counter rows.

**`apply` restriction.** Like `let`, a policy containing `for` cannot
be an `apply` target — `apply` inlines a pure predicate, which has no
walk to run iterations in.

**Update-group note.** Iterating `route.communities` / `route.as-path`
/ a set reads no peer identity and never disqualifies update-group
sharing; a `peer.*` read *inside* a loop body counts exactly as it
would outside.

Migration example — an FRR/BIRD-style AS-path bogon check without a
regex:

```rpol
# Before: anchored regex over the rendered path string.
policy bogon-guard-regex {
    term walk { if route.as-path matches "_(64512|65535)_" { reject } accept }
}

# After: typed iteration + one hash probe per ASN; the set is
# maintainable data, not pattern syntax.
asn-set bogon-asns { 64512, 65535 }
policy bogon-guard {
    term walk {
        for asn in route.as-path {
            if asn in bogon-asns { reject }
        }
        accept
    }
}
```

### Functions — `fn`

`fn NAME(param: u32, ...) -> u32 { ... }` names a pure computation
over `u32` values (ADR-0103 Decision 2, LAN-304):

```rpol
fn penalty(len: u32, weight: u32) -> u32 {
    let base = len * weight
    min(base, 1000)
}

policy p {
    term dampen { if penalty(route.as-path.len, 10) >= route.med { reject } }
    term rest { accept }
}
```

`fn` is a top-level contextual identifier like statement-`let`: top
level previously admitted no bare identifier, so existing names keep
working. Functions get their own namespace — duplicate `fn` names are
errors, but a set or policy may share a function's name (every
reference position is disjoint); the builtin names `min`/`max`/`clamp`
are reserved and cannot be shadowed.

**Bodies are expression-shaped.** A body is zero or more `let`
bindings followed by exactly **one result expression** — the
last-expression rule; there is no `return`. Verdicts, `set`/`add`/
`remove`/`prepend`, `if`, and `for` are policy-term territory and get
a typed diagnostic inside a body (`if` would need expression-`if`,
which does not exist in the language — `min`/`max`/`clamp` cover
selection; a later slice may revisit). Parameters and return values
are `u32` this slice, and the return type is spelled explicitly
(`-> u32`).

**Closed over nothing (normative).** A function body may not read
`route.*`/`peer.*` fields — every input arrives as a parameter, so a
function is a pure function of its arguments. This is what keeps the
hot-path analyses call-site-local: `penalty(peer.asn, 10)` counts
toward `requires_peer_context` because the *argument* reads peer
identity; `penalty(route.as-path.len, 10)` never disqualifies
update-group sharing, no matter what the body does. The compile error
says to pass the field as an argument.

**No recursion.** The call graph must form a DAG — direct or mutual
recursion is a compile error naming the cycle, exactly like `apply`.
Call chains are depth-capped at 8 (`MAX_CALL_DEPTH`), enforced in the
same Kahn-ordered cost DP as the `apply` bounds.

**Full inlining (normative).** A call is compile-time sugar for a
scope of `let` bindings: each argument binds to a caller-frame slot
(named `fn.param` in explain surfaces), each body `let` to
`fn.binding`, and the result expression to a slot named by the
rendered call itself, which the call site reads. There are **no
runtime call frames** — evaluation walks the same flat term list as
before, and a program that never calls functions pays nothing.
Consequences:

- **Evaluation is eager, like `let`.** Arguments and the body evaluate
  when the walk reaches the statement containing the call — even if a
  `&&` short-circuit would have skipped the value — so a call that
  errors (checked arithmetic; functions are pure and terminating but
  *not* total) denies the route on the uniform eval-error rail
  whenever its statement executes.
- **Term identity survives.** The inlined binds become `<term>.<n>`
  IR terms of the *calling* term (the established multi-term split
  naming), so the counter grid and trace skeleton stay a function of
  the source; per-function hit counting is explicitly out of scope
  (Decision 6.3 — it would need runtime call frames).
- **Attribution names both sides.** An error inside a body renders
  with the calling term's name and the qualified binding, e.g.
  `term compute.3: let share.each = share.total / share.parts [matched]`
  followed by
  `term compute.3: evaluation error: division by zero — fail closed => reject`;
  the live-path WARN carries the same `(let share.each)` label.
  Guards render calls source-level:
  `penalty(route.as-path.len, 10) >= route.med`.
- **Budgets compound honestly.** The cost DP charges the fully-inlined
  body per call site, against the same `MAX_APPLY_EXPANSION` /
  `MAX_EVAL_COST` budgets as `apply` — a big body called from many
  sites is rejected at compile time. Inlined bodies also consume
  caller-frame binding slots (arguments + body lets + the result, per
  call site); a term whose calls exceed the 256-slot frame is a
  compile error at the term's span.

**Calling parity.** `penalty(a, b)` evaluates exactly like writing the
body inline — same verdicts, same modifications, zero fuel (calls are
straight-line code; only loop iterations meter) — pinned by test.

**`apply` restriction.** Like `let` and `for`, a policy that calls
functions cannot be an `apply` target: calls lower to binding terms a
pure inlined predicate cannot execute. Call the function in the
applying policy instead.

Migration example — factoring a computation repeated across policies
(the step beyond LAN-302's single-policy `let`):

```rpol
# Before: the damping formula is duplicated — and must be kept in
# sync — across two policies.
policy transit-in {
    term dampen { if min(route.as-path.len * 10, 1000) >= route.med { reject } }
    term rest { accept }
}
policy peer-in {
    term dampen { if min(route.as-path.len * 12, 1000) >= route.med { reject } }
    term rest { accept }
}

# After: one definition, weights at the call sites.
fn penalty(len: u32, weight: u32) -> u32 {
    let base = len * weight
    min(base, 1000)
}
policy transit-in {
    term dampen { if penalty(route.as-path.len, 10) >= route.med { reject } }
    term rest { accept }
}
policy peer-in {
    term dampen { if penalty(route.as-path.len, 12) >= route.med { reject } }
    term rest { accept }
}
```

### `route.family` — one chain, many families

`route.family` is the route's **typed** AFI/SAFI family, carried by the
evaluation context itself — never inferred from the shape of the
route's prefix (BGP-LS and RTC NLRIs have no prefix at all; a FlowSpec
rule's destination component is not its family). It lets one chain
attached to several families branch per family instead of being split
into near-identical per-family policies.

Migration example — before, two chains that differ only in one guard:

```rpol
policy edge-v4 { term dampen { if route.med >= 500 { reject } } term rest { accept } }
policy edge-v6 { term dampen { if route.med >= 800 { reject } } term rest { accept } }
```

after, one chain attached to both families:

```rpol
policy edge {
    term dampen-v4 { if route.family == ipv4-unicast && route.med >= 500 { reject } }
    term dampen-v6 { if route.family == ipv6-unicast && route.med >= 800 { reject } }
    term rest { accept }
}
```

Family predicates read no peer identity, so unlike `peer.*` or strict
next-hop they never push an export peer onto the ungrouped
`policy_peer_context` path — peers sharing the chain still share one
update group.

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
- A policy that declares `let` bindings cannot be applied (LAN-302):
  the inlined predicate has no term walk to execute bindings in. The
  compile error names the target's first `let`. The same rule covers
  `for` loops (LAN-303) and function calls (LAN-304 — a call is sugar
  for a scope of lets).

## Actions

| Action | Effect |
|---|---|
| `accept` / `reject` | terminal verdict (see evaluation order) |
| `set local-pref <u32 \| value-expr>` | override `LOCAL_PREF`, e.g. `set local-pref min(route.local-pref * 2, 400)` |
| `set med <u32 \| value-expr>` | override `MED`, e.g. `set med route.med + 50` |
| `set next-hop <ip>` / `set next-hop self` | override `NEXT_HOP` |
| `add community 65001:999` / `remove community ...` | standard communities |
| `add large-community 65000:1:2` / `remove ...` | large communities |
| `add ext-community RT:65001:100` / `remove ...` | extended communities (RT/RO, or well-known: `add ext-community OV_INVALID`) |
| `prepend as <asn> <count>` | prepend `<count>` copies of `<asn>` (count: literal 1–255) |
| `prepend as self\|peer\|origin <count>` | prepend a computed ASN (see below) |

The kind keyword must match the literal's kind (`add community
RT:...` is a compile error pointing at `add ext-community`). Within a
policy, later `set`s of the same attribute win; across a chain, the
existing merge semantics apply (later policy wins scalars, add/remove
lists merge with later-policy-wins cancellation). Literal and computed
prepends share one scalar slot: a later prepend of either form
replaces an earlier one of either form; computed `set` values share
their attribute's slot the same way. A computed `set` value resolves
when the matched term's action executes — constant expressions have
already folded to literals at compile time, and expressions reading
route/peer fields evaluate per route (an evaluation error denies the
route; see "Value expressions").

### Computed prepend operands

`prepend as` also takes a computed operand instead of a literal ASN:

- **`self`** — the local speaker's ASN (the daemon's `[global] asn`,
  stamped onto the chain when it is attached; in-language tests state
  it with the `peer { local-as N }` fixture field).
- **`peer`** — the evaluation peer's ASN.
- **`origin`** — the route's origin AS: the last ASN of the rightmost
  non-empty `AS_SEQUENCE` (the same value `route.origin-as` reads).
  A policy *parameter* named `origin` shadows the operand — the
  parameter keeps its existing meaning.

**Direction legality.** `self` and `origin` are legal on import and
export chains. `peer` is **import-only**: on an export chain it would
prepend the *receiving* peer's own ASN, which the receiver rejects as
an own-AS loop (RFC 4271 §9.1.2) unless it runs allowas-in. A chain
using `prepend as peer` is rejected when it is attached as an export
chain (config load, reload, transaction) — a config error naming the
policy and term, never a per-route runtime surprise.

| operand  | import | export | notes |
|---|---|---|---|
| `self`   | yes | yes | outbound TE; inbound self-prepend biases best-path like the literal form already could |
| `peer`   | yes | **rejected at attach** | the inbound "prepend the neighbor's AS" idiom |
| `origin` | yes | yes | origin AS is already in the path — no loop-detection impact |

*Comparison:* FRR's `set as-path prepend last-as N` (prepend the
neighbor's AS) is its inbound route-map idiom and the model for
`prepend as peer`; FRR has no `self`/`origin` operands (operators
write literals). BIRD's `bgp_path.prepend()` takes only explicit ASN
values — no peer-derived operand exists there at all. Neither
implementation documents a legitimate outbound use of a
peer-AS prepend, hence the attach-time rejection.

**Failure is closed.** A computed operand resolves when the matched
term's action executes. If the value is unknown — no usable
`AS_SEQUENCE` for `origin`, unknown peer ASN for `peer`, a chain
evaluated outside a daemon config for `self` — or the context value is
zero (AS 0 is prohibited on the wire, RFC 7607), the route is
**denied**: staged modifications are discarded, ASN 0 is never
prepended, and explain traces name the failing term, operand, and
reason.

**Update-group note.** `prepend as peer` reads peer identity, so (like
`peer.asn` guards) it keeps its peers out of shared update groups;
`self` and `origin` never disqualify grouping.

Extended-community wire encoding follows the daemon's other
frontends: dotted-quad admin → RFC 4360 type 0x01, ASN > 65535 →
type 0x02, otherwise type 0x00 (subtype 0x02 RT / 0x03 RO).

## Tests

```rpol
test NAME {
    route { FIELD VALUE; ... }
    [peer { address IP; asn N; local-as N; group "NAME" }]
    expect POLICY[(args)] == accept|reject [with ASSERTION, ...]
    [expect ...]
}
```

Route fixture fields: `prefix`, `communities [..]`,
`large-communities [..]`, `ext-communities [..]`, `as-path "65001
65002"`, `next-hop`, `local-pref`, `med`, `rpki`, `aspa`,
`route-type`, `evpn-route-type`, `family`. Omitted fields are absent
attributes (so `local-pref`/`med` comparisons see the implicit 100/0,
`rpki` defaults to `not-found`, `aspa` to `unknown`; an omitted
`family` matches no family predicate — it is never derived from the
fixture's `prefix`). The fixture AS-path length is the
whitespace-word count of the string form; the fixture origin AS is
the last plain ASN outside `{...}` AS_SET braces (mirroring the
typed-path rule), so `as-path "65010 64500"` has origin 64500 and
`as-path "{64500 64501}"` has none.

`with` assertions check the evaluation result's **modifications**
(the frontend has no live route to apply them to): `local-pref N`,
`med N`, `next-hop IP|self`, `community LIT` (and
`large-community`/`ext-community`, asserting presence in the add
lists), `prepend as ASN COUNT`. Computed prepend operands resolve
during evaluation, so the assertion states the **resolved** ASN:
`peer { asn 65010 }` + `prepend as peer 3` asserts as
`with prepend as 65010 3`. `peer { local-as N }` supplies the value
`prepend as self` resolves to (omitted ⇒ it fails closed and the
expectation is a `reject`).

Tests run at check time (`rbgp policy check`, CI) with zero daemon
involvement. Testing a *candidate* policy against a live RIB is
`rbgp policy test` (below).

## Modules and imports

```rpol
import "lib/bogons.rpol"
import "lib/customers.rpol"

policy edge-in {
    term bogon { if route.prefix in bogons { reject } }        # from lib/bogons.rpol
    term customer { if route.prefix in customers { accept } }  # from lib/customers.rpol
}
```

`import "relative/path.rpol"` is a top-level declaration that splices
another file's definitions — sets, functions, policies, and `test`
blocks — into the compilation unit. Modules are a **resolution
feature, not a language feature** (ADR-0103): after resolution the
compiled artifact is indistinguishable from one concatenated source,
and only diagnostics remember file boundaries (an error in an imported
file renders an excerpt of *that* file).

**Resolution and roots.** Import paths must be relative. Each resolves
against the importing file's directory first, then against each
configured policy root in order — `[policy] rpol_roots` in the daemon
config, repeatable `--root DIR` for `rbgp policy check`. The resolved
file (after symlinks and `..` are canonicalized away) must stay inside
the main file's directory or one of the roots; escaping every root is
a compile error. There is no ambient working-directory lookup.

**One flat namespace.** All modules share a single namespace after
resolution; defining the same set/fn/policy/test name in two modules
is a compile error naming both files. This is the deliberate V1 shape
— shared libraries (bogon lists, customer sets, hygiene policies) get
short unprefixed names at every use site. Qualified names
(`bogons.martians`) and selective imports are compatible later
extensions if real collision pain shows up; today, rename at the
definition.

**Determinism and reload identity.** Imports resolve depth-first in
declaration order — never filesystem order — and each file loads once
(diamond imports are fine; cycles are compile errors naming the
cycle). The policy identity the reload planner compares is the
**resolved module graph's content**: editing an imported leaf makes
every unit that (transitively) imports it read as changed, while a
byte-identical graph reloads as a content-equal no-op regardless of
file paths. One unit compiles all-or-nothing — a broken or missing
import anywhere rejects the whole load and the running generation is
untouched.

**Budgets.** Import nesting ≤ 8; each file ≤ 1 MiB; a unit's total
source ≤ 8 MiB across ≤ 64 files. All enforced at load with
diagnostics; evaluation never touches the filesystem.

**Auditing.** `rbgp policy check FILE --list-deps [--root DIR]...`
prints the resolved graph — every module's canonical path, SHA-256
content hash, and imports — for packaging and change review.

Inline sources (`rbgp policy test`, the `TestPolicy` RPC) cannot
import: there is no filesystem to resolve against, and the diagnostic
says so. Check import-using files with `rbgp policy check`; the daemon
resolves them at config load / SIGHUP.

### Migration example — extracting a shared library

```rpol
# Before: every edge policy file carries its own bogon list.
prefix-set bogons { 10.0.0.0/8 le 32, 192.168.0.0/16 le 32, ... }
policy edge-in { term bogon { if route.prefix in bogons { reject } } ... }
```

```rpol
# lib/bogons.rpol — the shared library (sets, fns, even policies):
prefix-set bogons { 10.0.0.0/8 le 32, 192.168.0.0/16 le 32, ... }

# edge.rpol — after: one definition, imported where needed.
import "lib/bogons.rpol"
policy edge-in { term bogon { if route.prefix in bogons { reject } } ... }

test still-rejects-bogons {           # tests see imported names too
    route { prefix 10.1.0.0/24 }
    expect edge-in == reject
}
```

Because the resolved content is identical, this refactor reloads as a
no-op: no chain reinstall, no Route Refresh.

## Grammar sketch

```text
file        := (import-decl | prefix-set-def | community-set-def | asn-set-def | fn-def | policy-def | test-def)*
import-decl := "import" STRING                    # contextual `import` (LAN-300)
prefix-set-def    := "prefix-set" IDENT "{" [prefix-entry ("," prefix-entry)*] "}"
prefix-entry      := PREFIX ["ge" INT] ["le" INT]
community-set-def := "community-set" IDENT "{" [community ("," community)*] "}"
asn-set-def       := "asn-set" IDENT "{" [INT ("," INT)*] "}"
fn-def      := "fn" IDENT "(" [param ("," param)*] ")" "->" "u32"
               "{" fn-let* value "}"               # contextual `fn` (LAN-304)
fn-let      := "let" IDENT "=" value [";"]
policy-def  := "policy" IDENT ["(" param ("," param)* ")"] "{" term* "}"
param       := IDENT ":" "u32"
term        := "term" IDENT "{" stmt* "}"
stmt        := if-stmt | let-stmt | for-stmt | action [";"]
let-stmt    := "let" IDENT "=" value [";"]        # contextual `let` (LAN-302)
for-stmt    := "for" IDENT "in" for-source "{" stmt* "}"   # contextual `for` (LAN-303)
for-source  := "route" "." ("communities" | "as-path") | IDENT   # IDENT: asn-set
if-stmt     := "if" expr "{" body-stmt* "}" ["else" "{" body-stmt* "}"]
body-stmt   := let-stmt | action [";"]
action      := "accept" | "reject"
             | "break" | "continue"               # loop bodies only (LAN-303)
             | "set" ("local-pref" | "med") value
             | "set" "next-hop" (IP | "self")
             | ("add" | "remove") ("community" | "large-community" | "ext-community") community
             | ("add" | "remove") "community" IDENT      # binding-valued (LAN-303)
             | "prepend" "as" (u32arg | "self" | "peer" | "origin") INT
expr        := and ("||" and)*
and         := unary ("&&" unary)*
unary       := "!" unary | "(" expr ")" | "apply" "(" IDENT ["(" u32arg,* ")"] ")" | predicate
             | IDENT [arith-tail] ("=="|"!="|">="|"<=") value     # binding/parameter LHS
             | IDENT "in" IDENT            # binding vs asn-set / community-set (LAN-303)
predicate   := field (("=="|"!="|">="|"<=") (rhs | value) | "in" IDENT | "has" community
             | "matches" STRING | "contains" u32arg)
             | field arith-tail ("=="|"!="|">="|"<=") value    # LHS arithmetic
value       := mul (("+"|"-") mul)*                            # checked u32
mul         := atom (("*"|"/"|"%") atom)*
atom        := INT | STD-COMMUNITY | IDENT | field | "(" value ")"   # IDENT: parameter or binding
             | ("min"|"max") "(" value "," value ")"
             | "clamp" "(" value "," value "," value ")"
             | IDENT "(" [value ("," value)*] ")"  # user-function call (LAN-304)
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

## Using policies in the daemon

`.rpol` files become live daemon policy through `[policy] rpol_files`
in the config (full reference:
[`CONFIGURATION.md`](CONFIGURATION.md)):

```toml
[policy]
rpol_files = ["policies/core.rpol"]        # relative to the config file
rpol_roots = ["policies/lib"]              # extra `import` roots, same resolution

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
import_policy_chain = ["customer-in(200)", "bogon-filter"]
```

Every file compiles (parse + typecheck) at config load; diagnostics
are load errors. Policies join the same namespace as
`[policy.definitions]` TOML policies — chains mix both freely, and
parameterized policies are instantiated by call-form (`u32` arguments,
arity-checked at load). Editing a referenced file + SIGHUP hot-applies
the change to exactly the peers whose resolved chains moved, with
Route Refresh for materially changed import policy.

### `rbgp policy test` — dry-run against the live RIB

`rbgp policy check` runs a file's own `test` blocks locally (CI-able,
no daemon). `rbgp policy test` goes further: it sends the candidate
source to a running daemon, which compiles it server-side and
evaluates the selected policy **read-only over a snapshot of the live
RIB** — no route state changes, no session impact, no policy counters
move (`SensitiveRead` authorization).

```console
$ rbgp policy test policies/core.rpol --policy "customer-in(200)" \
    --direction import --peer 10.0.0.2 --show-changes 2
policy "customer-in(200)" (import) over 1204 routes:
  accepted 990  rejected 214  modified 990
Term hits:
  rpki-guard                       3
  customer-routes                  990
  bogon-guard                      211
Changes (up to 2):
  10.10.1.0/24 (from 10.0.0.2):
    local_pref 100 -> 200
    communities + 65001:999
  10.10.2.0/24 (from 10.0.0.2):
    local_pref 100 -> 200
    communities + 65001:999
```

- `--direction import` evaluates Adj-RIB-In routes (all peers, or one
  with `--peer`); `--direction export` evaluates Loc-RIB best routes,
  with `--peer` setting the peer context guards see (`peer.address`,
  `peer.asn`, `peer.group`).
- `--family ipv4_unicast|ipv6_unicast` filters the snapshot; V1 scope
  is IPv4/IPv6 unicast routes (other families are not walked).
- `--limit N` caps how many routes are evaluated; `--show-changes N`
  caps the before/after attribute diff samples.
- Compile diagnostics come back rendered exactly as `policy check`
  prints them (exit code 1); a clean run exits 0.
- `--json` emits the counts, per-term hits, and diffs structurally.

Per-term hit counters answer "which term is doing the work" (the
IOS-XR `show pcl` idea); a term lowered to several IR steps reports as
`name.1`, `name.2`, ....

### Explain — which term decided, and why

`.rpol` policies are first-class citizens of the daemon's explain
surfaces (ADR-0073 / ADR-0096 Decision 3.3):

- **`rbgp policy explain --neighbor A --prefix P`** (import): when the
  deciding chain member is an `.rpol` policy, the statement trace
  names the deciding **term** and lists every evaluated term with its
  guard rendered back to `.rpol` syntax and a matched / not-matched
  verdict:

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

  Guards render with sets shown by their source name; terms after the
  deciding one were never evaluated and carry no line. A term that
  modified without a verdict shows as `... => set med 5; continue`.
- **`rbgp rib advertised --explain`** (`ExplainAdvertisedRoute`,
  export): the policy attribution extends to `<chain-ref>:<term>` when
  the deciding member is `.rpol` — e.g.
  `export policy "customer-in(200):transit-guard" denied this route`.
  TOML members render unchanged.

### `rbgp policy stats` — live per-term hit counters

Where `policy test` counts hits over a one-shot dry run, `rbgp policy
stats` reads the **live** counters of the chains actually installed on
the daemon: every route evaluated on the import or export path bumps
its matched terms' counters (relaxed atomics — no measurable eval
cost), and the query snapshots them without resetting anything
(`SensitiveRead`).

```console
$ rbgp policy stats --peer 10.0.0.2 --direction both
10.0.0.2 export chain — 1204 routes evaluated since install
  POLICY                           TERM                     HITS
  customer-in(200)                 rpki-guard               3
  customer-in(200)                 customer-routes          990
  bogon-filter                     bogons                   211
10.0.0.2 import chain — 890 routes evaluated since install (install generation 2)
  POLICY                           TERM                     HITS
  customer-in(200)                 rpki-guard               1
  customer-in(200)                 customer-routes          889
```

- Counters read as **since chain install**: replacing a peer's chain
  (policy reload / hot-apply / gNMI Set) installs a fresh instance and
  resets its counters to zero. A reload that re-resolves a peer to a
  **content-equal** chain skips the reinstall entirely — the installed
  instance and its counters survive; only peers whose resolved chain
  content moved reset. A session flap does not reset the RIB-side
  export counters (the chain instance survives).
- TOML chain members count too; their unnamed statements report by
  `term_index` (`statement 0`, `statement 1`, ...).
- `--direction` selects **export** (the default), **import**, or
  **both**. Export chains are read from the RIB manager; import chains
  are read from each live session task, so a peer without a live
  session reports no import chain.
- Import chains report their **install generation** (bumps on every
  chain install), so counters that reset to zero read as a chain
  replacement, not continuous history. A session's initial chain
  reports generation 0; content-equal re-resolves are not reinstalled,
  so the generation moves only when the peer's resolved chain content
  does. Export chains do not track an install generation yet.
- Explain queries and `policy test` dry runs never move these
  counters — only live route evaluation counts.
- `--json` emits the rows structurally.

## Positioning — how `.rpol` differs from BIRD filters and route-maps

- **vs FRR/Cisco route-maps:** a route-map is an ordered list of
  numbered entries over external prefix-lists / community-lists /
  as-path access-lists, with `on-match next` for fallthrough. `.rpol`
  expresses the same decisions (the M80 lab proves outcome parity
  route for route) but sets are declared next to the policies that
  use them, terms have names instead of sequence numbers, guards are
  composable boolean expressions rather than implicit ANDs of match
  clauses, and policies take parameters — one `customer-in(peer_lp)`
  replaces a route-map per peer. Route-maps have no unit tests and no
  dry run; `.rpol` has both.
- **vs BIRD filters:** BIRD's filter language is a general-purpose
  interpreter — variables, arbitrary control flow, user-defined
  functions. `.rpol` is deliberately smaller: immutable bindings, only
  bounded `for` loops over finite sources, only pure non-recursive
  functions (fully inlined at compile time), no user types — so every
  policy terminates by construction and compiles to an indexed IR (a
  1,000-member set is one hash probe, not a linear scan). What BIRD can't do: test a candidate policy
  read-only against the *running* daemon's RIB (`rbgp policy test`),
  trace which term decided a live route (`rbgp policy explain`), or
  read per-term live hit counters (`rbgp policy stats`).
- **vs GoBGP/OpenConfig statements (and rustbgpd's own TOML):** the
  same evaluation engine underneath — `.rpol` and TOML policies
  compile to one IR and mix freely in chains — so `.rpol` is a
  frontend upgrade, not a fork: named sets, parameters, composition,
  and tests on top of chain semantics that behave exactly as before.

## Migrating from BIRD and FRR

One worked example covering the two newest predicate surfaces
together — an origin lock over an ASN set, branched per address
family. This is exactly the policy shape the M80 interop lab proves
outcome-equivalent against FRR route for route (import and export).

The `.rpol` version — one policy, attached to a dual-stack peer's
import chain:

```rpol
asn-set partners { 64999, 65100 }

policy partner-in {
    term partner-v4 {
        if route.family == ipv4-unicast && route.origin-as in partners {
            set local-pref 210;
            add community 65001:604;
            accept
        }
    }
    term partner-v6 {
        if route.family == ipv6-unicast && route.origin-as in partners {
            set local-pref 220;
            add community 65001:606;
            accept
        }
    }
    term rest { accept }
}
```

The FRR route-map spelling of the same intent. The origin lock
becomes one anchored as-path regex per member (re-matched against the
rendered path string on every evaluation — the `.rpol` set is one
hash probe); the family branch has no route-map keyword, so the
classic idiom is an any-prefix match of the wanted family (a v4
prefix-list entry never matches a v6 route and vice versa), with the
route-map applied in both address families:

```text
bgp as-path access-list PARTNERS seq 5 permit _64999$
bgp as-path access-list PARTNERS seq 10 permit _65100$
ip prefix-list ANY-V4 seq 5 permit 0.0.0.0/0 le 32
ipv6 prefix-list ANY-V6 seq 5 permit ::/0 le 128
!
route-map PARTNER-IN permit 10
 match as-path PARTNERS
 match ip address prefix-list ANY-V4
 set local-preference 210
 set community 65001:604 additive
!
route-map PARTNER-IN permit 20
 match as-path PARTNERS
 match ipv6 address prefix-list ANY-V6
 set local-preference 220
 set community 65001:606 additive
!
route-map PARTNER-IN permit 30
```

The BIRD filter spelling — `bgp_path.last` is the origin AS,
`net.type` the family:

```text
define PARTNERS = [ 64999, 65100 ];

filter partner_in {
    if bgp_path.last ~ PARTNERS then {
        if net.type = NET_IP4 then {
            bgp_local_pref = 210;
            bgp_community.add((65001,604));
            accept;
        }
        if net.type = NET_IP6 then {
            bgp_local_pref = 220;
            bgp_community.add((65001,606));
            accept;
        }
    }
    accept;
}
```

What carries over mechanically: BIRD's `bgp_path.last ~ [...]` and
FRR's anchored `_ASN$` regexes both become `route.origin-as in
<asn-set>`; BIRD's `net.type` checks and FRR's per-AF route-map
application both become `route.family ==` guards on one shared
policy. What has no equivalent to migrate: the in-file `test` blocks,
`rbgp policy test` dry runs against the live RIB, and per-term live
hit counters — those come free after the rewrite.

## Deliberate V1 exclusions

No `while` and no unbounded iteration of any kind — `for` (LAN-303)
iterates finite sources only, capped and fuel-metered. No
user-defined types, no maps (safety is total by construction —
ADR-0096 Decision 2; the ADR-0103 extension program adds bounded
constructs slice by slice — checked arithmetic shipped as LAN-299,
bindings as LAN-302, bounded loops as LAN-303, pure functions as
LAN-304, modules and imports as LAN-300). No `as-path-set`. No `else if` chains and no nested `if`
(keep terms small; use `&&` or more terms). No mutable state of any
kind — `let` bindings (LAN-302) are immutable, and reads never
observe staged `set` writes (read-back would break memoization and
needs its own ADR). EVPN route type takes only an integer literal
(no parameters — the value is wire-encoded u8). Full-form all-numeric
IPv6 literals (use `::` compression). These are scope decisions, not
parser accidents; each has an error message steering to the
supported form.
