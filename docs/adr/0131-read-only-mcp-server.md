# ADR-0131: Read-Only MCP Server for the Explain Surfaces

**Status:** Proposed
**Date:** 2026-09-05

## Context

The daemon already answers "why is this prefix not advertised to that peer?"
from live evaluation. `RibService.ExplainAdvertisedRoute` returns the ordered
export-gate ladder a route traverses toward a peer, recorded by a dry run of
the same staging body live distribution executes, so the explanation cannot
drift from the real decision. `PolicyService.ExplainImportPolicy`,
`RibService.ExplainBestPath`, and `PolicyService.ListRejectedRoutes` answer the
neighbouring questions.

Those answers reach operators through `rbgp` and the gRPC API. They do not
reach an AI agent, which is where a growing share of first-pass network triage
now happens. An agent asked the same question today answers it by inference
from route dumps and configuration text — exactly the guesswork the explain
surfaces exist to replace.

The Model Context Protocol is the interoperable way to close that gap: an MCP
host spawns a server as a subprocess and calls its declared tools. A read-only
MCP server over the explain RPCs would let an agent answer the question from
the daemon's own decision ladder.

Exposing a routing control plane to an agent is the part that needs a decision
record, not the plumbing. Three constraints shape it.

**There is no read-only tier to bind to.** `docs/reference/grpc-method-inventory.json`
reports `"read": 0` — of 111 methods, 66 are `sensitive_read`, 21 `mutating`,
24 `operator_only`. `sensitive_read` is the lowest tier a listener can be
capped at, and every method this server needs sits in it.

**The convenient local endpoint is the most privileged one.** An owner-only
Unix socket with no configured principal authorizes as the reserved implicit
principal `local-operator` at Operator tier — the highest. Filesystem ownership
is the authentication. Pointing an MCP server at the default local socket
therefore does not produce a read-only session; it produces the daemon's
strongest credential.

**Operators will be wary, and should be.** A process that takes instructions
from a language model is not something a serious network operator wants near a
production router. Any packaging that makes running it the default is wrong.

## Decision

### Ship a standalone, read-only MCP server as `tools/mcp`

`rustbgpd-mcp` is a `publish = false` workspace member with a lib and a bin
target, depending on `rustbgpd-api` for the generated gRPC client — the same
shape as `examples/event-bridge` and `examples/birdwatcher-adapter`. It depends
on neither `rustbgpctl`, `rustbgpd-rib`, nor `rustbgpd-mrt`. The lib target
exists so tests can call handler methods and inspect the registered tool router
directly.

The alternative considered was adding the MCP surface to the `rbgp` CLI. The
measurement below was run to settle it.

#### Placement measurement

Adding `rmcp 3.2.0` (`default-features = false`, features `server`, `macros`,
`transport-io`) plus `schemars` to `crates/cli/Cargo.toml` and rebuilding
`rbgp`, on a warm target directory:

| Measure | Before | After | Delta |
|---|---|---|---|
| `target/debug/rbgp` | 227,467,840 B | 227,635,808 B | +167,968 B (+0.07%) |
| `target/release/rbgp` | 10,695,176 B | 10,697,352 B | +2,176 B (+0.02%) |
| `cargo build -p rustbgpctl --bin rbgp` (debug) | 21.06 s | 20.50 s | within noise |
| `cargo build --release -p rustbgpctl --bin rbgp` | 1 m 32 s | 1 m 43 s | +11 s |
| `cargo tree -p rustbgpctl -e normal \| grep -c rustbgpd-rib` | 0 | 0 | unchanged |

Twenty crates enter the graph: `rmcp`, `rmcp-macros`, `schemars`,
`schemars_derive`, `serde_derive_internals`, `chrono`, `num-traits`, `futures`,
`futures-executor`, `futures-io`, `futures-macro`, `darling`, `darling_core`,
`darling_macro`, `dyn-clone`, `ref-cast`, `ref-cast-impl`, `getrandom`,
`pastey`, `uuid`.

The binary-size numbers are a floor, not the real cost: the experimental
`rbgp` never *called* rmcp, so link-time dead-code elimination removed nearly
all of it. What the measurement does establish is the part that matters for
this decision — the dependency-graph and build-time cost is paid by every
`rbgp` build whether or not the operator wants MCP, and `rustbgpd-rib` stays
out of the CLI either way (the 230 MB → 337 MB regression that rule exists to
prevent is not in play here).

A separate crate keeps the cost opt-in and keeps the MCP surface out of a
binary operators run on routers. That is decisive independently of the byte
counts, which is why the standalone crate is the decision.

#### Dependency pins

`rmcp 3.2.0`, verified against the crates.io registry on 2026-09-05
(`cargo search rmcp` reported `rmcp = "3.2.0"`). Pinned as a caret requirement
in `[workspace.dependencies]`, held out of Dependabot's grouped Cargo updates
in its own `mcp-sdk` group with major versions ignored: rmcp majors have
carried breaking API changes, so a major bump is a deliberate, separately
reviewed change rather than something that arrives batched with a tokio patch
release.

`schemars` needs **no exact pin here.** rmcp's `Json<T>` bound is satisfied
only by the schemars instance rmcp itself compiles against, which is what
forces an exact pin in projects on rmcp 1.7. rmcp 3.2.0 requires
`schemars = "1.0"` as a caret requirement (with the `chrono04` feature), which
unifies with this workspace's existing `schemars = "1.2"` onto a single
resolved `schemars 1.2.2` — verified with `cargo tree -p rmcp -e normal`. rmcp
3.x additionally re-exports the crate as `rmcp::schemars`, so even a future
divergence has a non-pinning remedy. Copying the `=1.2.1` pin from a project on
an older rmcp would have been wrong.

The feature set pulls no HTTP stack: `cargo tree -p rmcp -e normal` shows no
`axum`, no `hyper`, and no `tower` — not even `tower-service`, which rmcp gates
behind its own `tower` feature. `chrono` enters through rmcp's `schemars`
feature selection.

### Six tools, `rbgp_`-prefixed

`rbgp_explain_export`, `rbgp_explain_import`, `rbgp_explain_best_path`,
`rbgp_list_rejected`, `rbgp_list_peers`, `rbgp_get_health`. The prefix matches
the CLI binary operators already know.

`rbgp_explain_export` is the headline: it surfaces the whole `gates` ladder in
evaluation order with each rung's gate name, code, verdict, and detail, plus a
`stopped_at_gate` field naming the rung that halted the route. `rbgp_list_rejected`
surfaces `retention_enabled` and `capacity` alongside the listing and states in
words what an empty list means, because an empty list with retention disabled
means something completely different from an empty list with retention on.

#### Scope corrections

Two tools from the original scope cannot be built and are not faked:

- **No BMP RPC exists.** BMP is outbound-only export to configured collectors
  (`crates/bmp`); the proto has no BMP service. A BMP tool would require a new
  read RPC first.
- **No support-bundle RPC exists.** `rbgp doctor` assembles its bundle
  client-side from several RPCs plus local file and network probes. Reproducing
  it in an MCP server means reproducing those local probes, which is a separate
  decision — a support bundle is a redaction contract, not a query.

### Read-only by two independent controls

Neither control is sufficient alone, and the documentation says so.

**Control 1 — no write tool exists in the binary.** Not hidden, not gated at
call time: absent. Each tool declares the gRPC method path it calls in
`TOOL_METHOD_PATHS`, and `tools/mcp/tests/inventory_contract.rs` reads
`docs/reference/grpc-method-inventory.json` and fails the build if any declared
path is missing from the inventory, carries a `mutating` or `operator_only`
tier, or is declared twice. A companion unit test asserts the declared set
equals the set the tool router actually registers, so a tool cannot be added
without also entering the contract. The inventory is a machine-readable export
of the static table in `crates/api/src/authz.rs`, kept in step with it by
`machine_readable_inventory_matches_method_matrix`. It carries no request or
response types, so it cannot generate tool schemas — it can only police the
tool list, which is exactly what it is used for.

The mechanism was negative-controlled during development: adding
`/rustbgpd.v1.ControlService/Shutdown` to the table failed the contract test
with the tier named.

**Control 2 — the documented deployment.** The server runs on the operator's
workstation and connects to a listener capped at `max_tier = "sensitive_read"`
whose principal maps to the `observer` role. This is a property of one daemon's
configuration, which the server cannot verify and does not attempt to.

The reason neither suffices: control 2 is absent by default on the endpoint
most people will reach for. A colocated server on an owner-only UDS with no
principal gets Operator-tier credentials, and control 1 is the only thing
between those credentials and a write. Conversely control 1 lives in this
source tree, not in the daemon — it constrains this binary and nothing else, so
a correctly capped listener stays worthwhile.

### Deployment posture: workstation, not router

An stdio MCP server is spawned as a subprocess by the MCP host on the machine
where the operator sits, and it is a gRPC client. The recommended deployment
therefore adds **no process to the router**: it runs on the workstation and
connects to a capped remote listener like any other API client. Colocating it
on the daemon host is documented as the sharp edge, with the `local-operator`
tier consequence spelled out.

### Packaging: source only, opt-in build, shipped nowhere

The binary is deliberately absent from every release artifact. It is not in
the release tarball's copy list, not in the deb or rpm payload
(`packaging/nfpm.yaml`), and not in any container image. Every packaging step
copies binaries by name, so nothing picks it up implicitly — verified against
the release workflow, the packaging manifest, and the Dockerfile.

The workspace gains a `default-members` list containing every member except
`tools/mcp`, so a plain `cargo build` does not pay the MCP SDK compile cost.
CI and the local gates pass `--workspace` or an explicit `-p` everywhere it
matters, so the crate stays fully built, linted, and tested; the exclusion
changes only the implicit default set.

The crate stays **in this repository**. Splitting it out would turn the
inventory contract test into a cross-repo synchronization problem: it reads
`docs/reference/grpc-method-inventory.json` and depends on `rustbgpd-api`
generated from `proto/rustbgpd.proto`, both of which live here. This project
already carries one open gap of exactly that shape, where CI cannot see a path
dependency in a sibling repository; deliberately creating a second instance
would repeat a known failure. An in-repo crate, excluded from the default build
and from every shipped artifact, is the maximum separation that keeps the
contract test real.

Building an installable artifact for it — a separate, clearly labelled release
asset — is a possible follow-on and is explicitly not done here.

## Consequences

**Positive.** The defining question is answered from the daemon's own ladder.
Captured against a live daemon on 2026-09-05, `rbgp_explain_export` for a
prefix an export policy blocked returned `"decision": "deny"`, a seven-rung
ladder (`best_route`, `split_horizon`, `rr_reflection`, `family`, `llgr`,
`orf`, `export_policy`), `"stopped_at_gate": "export_policy"`, and the deciding
policy named in the rung's detail. The same query before the policy change
returned `"advertise"` with a nine-rung all-pass ladder ending at
`adj_rib_out`. That is the product claim, demonstrated rather than asserted.

The read-only property is mechanical. "A write RPC cannot leak into the tool
surface" is a failing test, not a promise in a README, and it is checked
against the same table the daemon authorizes from.

The tool surface is small and honest about what it cannot answer. `rbgp_list_rejected`
cannot report "no rejected routes" when retention is off; `rbgp_explain_import`
distinguishes `cache_disabled`, `no_session`, and `evicted` from a rejection.

**Negative.** A twentieth-order dependency surface enters the workspace lock
file for a binary nobody ships. `chrono` in particular arrives only because
rmcp selects it through its `schemars` feature.

rmcp is young and its majors break. The Dependabot exclusion means an rmcp
major sits unpatched until someone picks it up deliberately — the right
trade for a non-shipped tool, but it is a maintenance obligation, not a
free win.

The safety model rests partly on documentation. Control 1 holds unconditionally;
control 2 is advice an operator can ignore by pointing the server at the
default local socket, which works and gives the process Operator-tier
credentials. The how-to states this plainly rather than assuming it away.

**Neutral / outstanding.** Unit coverage is the pure mapping logic — request
construction, response to structured result, error mapping, truncation
accounting, label rendering — plus the stdio end-to-end handshake against the
compiled binary and the inventory contract. There is no in-repo mock gRPC
server harness to drive handler methods against a faked backend, and none was
built for this; `tests/birdwatcher_adapter_smoke.rs` stands up a real daemon
and a hand-rolled BGP speaker, which is the pattern to reuse if that coverage
is wanted later.

The six tools are a vertical slice, not a complete operator surface. The
remaining explain surfaces (`rbgp policy stats`, `rbgp doctor`, RPKI validation,
EVPN explain) are unaddressed, and whether they belong in an MCP tool list at
all is a question this ADR does not answer.
