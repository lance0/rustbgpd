# Answer route questions from an AI agent

> **Document class: CURRENT.** This maintained page reflects the project as it is now; dated sections remain bounded to their stated scope.

`rustbgpd-mcp` exposes the daemon's explain surfaces to an AI agent over the
Model Context Protocol, so "why is 203.0.113.0/24 not advertised to AS64502?"
is answered by the daemon's own export-gate ladder instead of inferred from
route dumps.

[All documentation](../README.md)

## Where this runs, and why that matters

**It does not run on the router.** An stdio MCP server is a subprocess the MCP
host spawns on the machine where the operator sits, and it is a plain gRPC
client. Adopting it adds no process to the daemon host: it runs on the
workstation and connects to a listener over the network, like `rbgp` or any
other API client.

That is the honest answer to "do I want an AI-facing process in my production
environment" — in the recommended deployment, you are not putting one there.

The binary is shipped in no release artifact and is excluded from the default
workspace build. Build it explicitly when you want it:

```sh
cargo build --release -p rustbgpd-mcp
```

## Configure a read-only listener on the daemon

Every tool this server exposes calls a `sensitive_read` gRPC method. Cap the
listener there and map its principal to the `observer` role:

```toml
[global.telemetry.grpc_tcp]
address = "10.0.0.1:50051"
max_tier = "sensitive_read"
token_file = "/etc/rustbgpd/mcp-observer.token"
principal = "mcp.observer"

[security.grpc.roles]
"mcp.observer" = "observer"
```

`max_tier` is a hard per-listener ceiling and `observer` is the lowest role
that reaches `sensitive_read`. A mutating call over this listener is refused by
the daemon before the handler runs:

```text
permission denied: listener max_tier sensitive_read does not permit
operator_only RPC /rustbgpd.v1.InjectionService/AddPath
```

gRPC authorization is startup configuration. Changing it needs a daemon
restart, not a reload.

For a TLS deployment, give the listener the `tls_cert_file` / `tls_key_file` /
`tls_client_ca_file` trio instead of a bearer token and point `--grpc-addr` at
`https://`. See [configuration](../reference/configuration.md) for the full
listener contract.

## Register the server with an MCP host

`--print-config` emits paste-ready `mcpServers` JSON. It renders a placeholder
for the token path and never echoes a token value:

```sh
rustbgpd-mcp --grpc-addr https://10.0.0.1:50051 \
  --grpc-token-file /etc/rustbgpd/mcp-observer.token --print-config
```

```json
{
  "mcpServers": {
    "rustbgpd": {
      "command": "/usr/local/bin/rustbgpd-mcp",
      "args": [
        "--grpc-addr",
        "https://10.0.0.1:50051",
        "--grpc-token-file",
        "/path/to/rustbgpd-observer.token"
      ]
    }
  }
}
```

Replace the placeholder path with the real token file before pasting. For
Claude Code:

```sh
claude mcp add rustbgpd -- /usr/local/bin/rustbgpd-mcp \
  --grpc-addr https://10.0.0.1:50051 \
  --grpc-token-file /etc/rustbgpd/mcp-observer.token
```

`--grpc-addr` and `--grpc-token-file` also read `RUSTBGPD_GRPC_ADDR` and
`RUSTBGPD_GRPC_TOKEN_FILE`.

## What the agent can ask

| Tool | Question it answers |
|------|---------------------|
| `rbgp_explain_export` | Why is this prefix advertised, or not advertised, to this peer? |
| `rbgp_explain_import` | Why did this prefix from this peer get accepted or rejected? |
| `rbgp_explain_best_path` | Which path won for this prefix, and at which decision step? |
| `rbgp_list_rejected` | What did this peer send that was thrown away? |
| `rbgp_list_peers` | What sessions exist and what state are they in? |
| `rbgp_get_health` | Is the daemon up, and how much is in the RIB? |

`rbgp_explain_export` returns the full export-gate ladder in live evaluation
order. Against a daemon whose export policy blocks the prefix:

```json
{
  "decision": "deny",
  "prefix": "203.0.113.0/24",
  "peer_address": "192.0.2.2",
  "stopped_at_gate": "export_policy",
  "gates": [
    { "step": 1, "gate": "best_route",     "code": "local_route",     "verdict": "pass" },
    { "step": 2, "gate": "split_horizon",  "code": "split_horizon",   "verdict": "pass" },
    { "step": 3, "gate": "rr_reflection",  "code": "rr_reflection",   "verdict": "pass" },
    { "step": 4, "gate": "family",         "code": "family",          "verdict": "pass" },
    { "step": 5, "gate": "llgr",           "code": "llgr",            "verdict": "pass" },
    { "step": 6, "gate": "orf",            "code": "orf",             "verdict": "not_applicable" },
    { "step": 7, "gate": "export_policy",  "code": "policy_denied",   "verdict": "stop",
      "detail": "export policy \"block-doc-prefix\" denied this route" }
  ]
}
```

The `detail` fields are elided above for width; the real response carries one
on every rung. A `stop` verdict names the gate that halted the route, and the
ladder is recorded by a dry run of the same staging body live distribution
executes — it cannot drift from the real decision.

Two surfaces the agent must not be allowed to misread, and which the tools
label explicitly:

- `rbgp_list_rejected` returns `retention_enabled` and a `retention_note`. When
  retention is off, an empty list is a configuration fact, not "nothing was
  rejected". When the store is at `capacity`, older rejections were displaced.
- `rbgp_explain_import` outcomes `cache_disabled`, `no_session`, and `evicted`
  mean the question could not be answered. They are not rejections.

Two tools that might be expected are absent because the RPCs do not exist: BMP
is outbound-only export to configured collectors with no query surface, and the
`rbgp doctor` support bundle is assembled client-side from several RPCs plus
local probes.

## How "read-only" is actually enforced

Two independent controls. **Neither is sufficient alone.**

**1. No write tool exists in the binary.** Not hidden, not gated at call time —
absent. Each tool declares the gRPC method it calls, and a contract test reads
[`grpc-method-inventory.json`](../reference/grpc-method-inventory.json) — the
machine-readable export of the daemon's own authorization table — and fails the
build if any declared method carries a `mutating` or `operator_only` tier. A
companion test asserts the declared set equals what the server actually
registers, so a tool cannot be added without entering the contract.

**2. The listener configuration above.** This is a property of one daemon's
config. The server cannot verify it and does not try.

### The colocation sharp edge

If you run the server on the daemon host against the local Unix socket, read
this. An owner-only UDS with no configured `principal` authorizes as the
reserved implicit principal `local-operator` **at Operator tier** — the
daemon's highest. Filesystem ownership is the authentication. So:

```sh
# Gives this process Operator-tier credentials on the daemon.
rustbgpd-mcp --grpc-addr unix:///var/lib/rustbgpd/grpc.sock
```

Control 2 is simply not present in that configuration, and control 1 — the
absence of any write tool in this binary — is the only thing standing between
those credentials and a write.

There is no lower tier to fall back to. The daemon publishes **zero**
`read`-tier methods; `sensitive_read` is the lowest cap a listener can carry,
and every explain RPC sits in it. Capping a UDS listener at `sensitive_read`
and giving it an explicit `principal` mapped to `observer` restores control 2
if colocation is unavoidable.

## Related

- [Explain route decisions](explain.md) — the same answers through `rbgp`.
- [gRPC method inventory](../reference/grpc-method-inventory.md) — every method
  and its authorization tier.
- [Configuration](../reference/configuration.md) — listener, tier, and role
  contracts.
- [ADR-0131](../adr/0131-read-only-mcp-server.md) — why this exists and what it
  deliberately does not do.
