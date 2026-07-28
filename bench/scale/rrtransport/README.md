# rrtransport

`rrtransport smoke` is a fixed-shape correctness harness for the real
route-reflector transport path. It starts a production `RibManager`, two
production transport sessions over TCP loopback, and the existing
`rustbgpd-evpn-load` peer handshake/decoder. Four synthetic ingress sources
inject exactly 100 unique IPv4 `/24` routes through `RibUpdate::RoutesReceived`.
Each target listener remains bound while its actual ephemeral address is given
to rustbgpd, then that exact socket is transferred into the peer handshake.

The smoke preloads the RIB before registering either target session, then
asserts one shared update group, exact staged Adj-RIB-Out counts, and exact
wire-side initial-dump prefix sets through each IPv4 End-of-RIB. It prints one
stable JSON receipt and a human summary. It is deliberately not a benchmark:
the shape is fixed and it makes no latency, throughput, RSS, or competitor
claim.

Run from the repository root:

```text
cargo run --manifest-path bench/scale/rrtransport/Cargo.toml --locked -- smoke
```
