# peer-loop

A minimal BGP speaker whose rustbgpd dependencies are `rustbgpd-wire` and
`rustbgpd-fsm`: the "minimal speaker" consumer from
[`docs/EMBEDDING.md`](../../docs/EMBEDDING.md) section 3.3. It links no RIB,
policy, or session-runtime workspace crate.

What it does:

- dials one peer over TCP
- drives the RFC 4271 FSM to Established (IPv4 unicast, 4-octet AS)
- sends KEEPALIVEs on the negotiated timer
- prints each successfully parsed UPDATE: announced and withdrawn prefixes plus
  a compact attribute summary
- exits non-zero when the session ends: NOTIFICATION received or sent,
  hold-timer expiry, or a closed connection

The FSM owns no I/O. The binary owns the socket and the timers, turns socket and
timer outcomes into `Event`s, and handles the required socket, timer, and
session actions the FSM returns.

## Run

```sh
cargo run -p peer-loop -- \
  --peer 192.0.2.1 --local-asn 65001 --remote-asn 65002 --router-id 192.0.2.2
```

Options: `--port` (default 179) and `--hold-time` in seconds (default 90; 0
disables the hold and keepalive timers). Port 179 on the peer side needs no
privilege here; only listening on it would.

Sample output:

```text
connected to 192.0.2.1:179
state Idle -> Connect
state Connect -> OpenSent
state OpenSent -> OpenConfirm
state OpenConfirm -> Established
established peer-as=65002 peer-id=192.0.2.1 hold=90s keepalive=30s families=[(Ipv4, Unicast)]
update announced=[198.51.100.0/24] withdrawn=[] attributes=[origin=IGP as-path=[65002] next-hop=192.0.2.1]
```

## Self-check

```sh
cargo test -p peer-loop
```

The loopback tests run the same session loop against a hand-driven responder
built from the wire crate. They cover Established, Extended Message framing, a
keepalive sent on the negotiated timer, one UPDATE printed with its prefix and
attributes, NOTIFICATION exit, and hold-timer expiry. They need neither an
external network nor a running daemon.
