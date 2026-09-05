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

The binary is shipped in no release artifact. Plain `cargo build` keeps its
existing root-package default; build the MCP server explicitly when needed:

```sh
cargo build --release -p rustbgpd-mcp
```

## Configure a read-only listener on the daemon

Every tool calls a `sensitive_read` gRPC method. For remote access, configure
mutual TLS, cap the listener there, and map the client certificate's principal
to the `observer` role. This example uses a client certificate with URI SAN
`rustbgpd://observer/mcp`:

```toml
[global.telemetry.grpc_tcp]
address = "10.0.0.1:50051"
max_tier = "sensitive_read"
tls_cert_file = "/etc/rustbgpd/pki/server.crt"
tls_key_file = "/etc/rustbgpd/pki/server.key"
tls_client_ca_file = "/etc/rustbgpd/pki/client-ca.pem"

[security.grpc.roles]
"rustbgpd://observer/mcp" = "observer"
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

The MCP client needs the server's CA and its own client certificate/key.
`https://` requires all three `--grpc-tls-*-file` options below. The endpoint's
host must match the server certificate; `--grpc-tls-server-name` can select a
different verification name. TLS options are rejected with `http://` and
`unix://` endpoints. Do not set `grpc_tcp.principal` on a mutual-TLS listener:
the daemon derives it from the verified client certificate.

For an existing bearer-token listener, use `--grpc-token-file` with the
appropriate endpoint. See [configuration](../reference/configuration.md) for
the listener's token, principal, and role settings.

## Register the server with an MCP host

`--print-config` emits `mcpServers` JSON with placeholders for credential-file
paths. It never echoes token values or certificate/key contents:

```sh
rustbgpd-mcp --grpc-addr https://10.0.0.1:50051 \
  --grpc-tls-ca-file /etc/rustbgpd/pki/server-ca.pem \
  --grpc-tls-cert-file /etc/rustbgpd/pki/mcp-client.crt \
  --grpc-tls-key-file /etc/rustbgpd/pki/mcp-client.key --print-config
```

```json
{
  "mcpServers": {
    "rustbgpd": {
      "args": [
        "--grpc-addr",
        "https://10.0.0.1:50051",
        "--grpc-tls-ca-file",
        "/path/to/ca.pem",
        "--grpc-tls-cert-file",
        "/path/to/client.crt",
        "--grpc-tls-key-file",
        "/path/to/client.key"
      ],
      "command": "/usr/local/bin/rustbgpd-mcp"
    }
  }
}
```

`command` is the running binary's own path. Replace the credential-file
placeholders with paths readable by the MCP host before using the snippet.

For Claude Code:

```sh
claude mcp add rustbgpd -- /usr/local/bin/rustbgpd-mcp \
  --grpc-addr https://10.0.0.1:50051 \
  --grpc-tls-ca-file /etc/rustbgpd/pki/server-ca.pem \
  --grpc-tls-cert-file /etc/rustbgpd/pki/mcp-client.crt \
  --grpc-tls-key-file /etc/rustbgpd/pki/mcp-client.key
```

`--grpc-addr` and `--grpc-token-file` also read `RUSTBGPD_GRPC_ADDR` and
`RUSTBGPD_GRPC_TOKEN_FILE`. The TLS options read `RUSTBGPD_GRPC_TLS_CA_FILE`,
`RUSTBGPD_GRPC_TLS_CERT_FILE`, `RUSTBGPD_GRPC_TLS_KEY_FILE`, and
`RUSTBGPD_GRPC_TLS_SERVER_NAME`.

Each tool call has a 30-second backend response deadline, including connection
readiness and the complete decoded response body. A stalled daemon or response
path returns an error; the MCP server does not retry the call automatically.

## What the agent can ask

| Tool | Question it answers |
|------|---------------------|
| `rbgp_explain_export` | Why is this prefix advertised, or not advertised, to this peer? |
| `rbgp_explain_import` | Why did this prefix from this peer get accepted or rejected? |
| `rbgp_explain_best_path` | Which path won for this prefix, and at which decision step? |
| `rbgp_explain_evpn_route` | What happened to this exact EVPN route — selection and export? |
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

`rbgp_explain_evpn_route` covers the EVPN side and answers more per call: one
response carries the selection story (installed best, fresh selection, compared
candidate, candidate count, deciding reason) and, when `advertised_to` is given,
the same gate ladder toward that peer. Keys are exact, not filters — a Type 2
lookup with `ip` omitted selects the MAC-only key, not every host IP under that
MAC:

```json
{
  "rd": "65001:100",
  "key": { "route_type": "mac_ip", "ethernet_tag": 0, "mac": "aa:bb:cc:dd:ee:01" },
  "received_from": "192.0.2.1",
  "advertised_to": "192.0.2.9"
}
```

### Results an agent must not over-read

Empty is not the same as absent, and absent is not the same as denied. Four
results say which case they are in, so the distinction does not depend on a
model inferring it:

- `rbgp_list_rejected` returns `retention_enabled` and a `retention_note`. When
  retention is off, an empty list is a configuration fact, not "nothing was
  rejected". An enabled store describes currently retained entries: subsequent
  acceptance or withdrawal removes entries, so an empty store does not prove
  there were no earlier rejections. `evictions_since_reset` reports known
  displacement; occupancy alone cannot establish whether eviction occurred.
  `truncated_by_limit` reports entries omitted from this response by `limit`.
- `rbgp_explain_import` outcomes `cache_disabled`, `no_session`, and `evicted`
  mean the question could not be answered. They are not rejections.
- `rbgp_explain_evpn_route` returns a `received_note`. EVPN import rejection
  history is not retained, so an empty `received` for a peer is **not** an
  import-rejection explanation and **not** proof the peer never sent the key —
  it supports no conclusion about what the peer sent. The note also separates
  that case from "no accepted-source lookup was requested".
- `rbgp_explain_evpn_route` returns a `selection_note`. While
  `selection_deferred` is set the installed `best` may differ from fresh
  selection, so reporting it as current state would be wrong; the note says so
  and points at `selection_best`.

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

## Integration coverage

The workspace test suite runs the actual MCP binary against a disposable daemon
with an Established IPv4 peer. It checks the export-explain allow/deny ladder
across a policy reload, JSON-RPC stdout, and mutation refusal on the same
observer listener used by the adapter. Fixture setup uses a separate operator
connection. This does not establish live coverage of every tool or EVPN case;
the mock transport tests separately cover mutual TLS and stalled responses.

To run this check alone, build the source-only adapter first:

```sh
cargo build --locked -p rustbgpd-mcp --bins
cargo test --locked -p rustbgpd --test mcp_smoke
```

`cargo test --locked --workspace` builds both executables automatically. A
focused run fails with build instructions if the adapter binary is missing.

## Related

- [Explain route decisions](explain.md) — the same answers through `rbgp`.
- [gRPC method inventory](../reference/grpc-method-inventory.md) — every method
  and its authorization tier.
- [Configuration](../reference/configuration.md) — listener, tier, and role
  contracts.
- [ADR-0131](../adr/0131-read-only-mcp-server.md) — why this exists and what it
  deliberately does not do.
