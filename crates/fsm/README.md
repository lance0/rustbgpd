# rustbgpd-fsm

Pure RFC 4271 BGP finite state machine. No I/O, no async runtime, no
sockets — just `handle_event(&mut self, Event) -> Vec<Action>` over an
in-place `SessionState`.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Design

The FSM is intentionally isolated from all I/O concerns. The transport
layer feeds events in and executes the resulting actions. This makes the
FSM trivially testable and enables property-based testing of state
transitions.

All six RFC 4271 states are implemented: Idle, Connect, Active,
OpenSent, OpenConfirm, Established. Capability negotiation (4-octet AS,
multi-protocol, Add-Path, experimental Paths-Limit, graceful restart,
extended messages) is handled during OPEN exchange. Paths-Limit is applied
only to matching negotiated Add-Path send families; negotiated state exposes
the peer-advertised and effective family-local limits.

## Compatibility

`rustbgpd-fsm 0.3.0` moved with `rustbgpd-wire 0.15.0`: the FSM's public API
exposes wire types, so the incompatible wire dependency required the paired
0.x breaking bump. That cut marked `TimerType` and `error::FsmError`
`#[non_exhaustive]`, joining `Event`, `Action`, `PeerConfig`, and
`NegotiatedSession` — match them with a wildcard arm, and future variant
additions become non-breaking. `SessionState` remains exhaustively
matchable: the six RFC 4271 §8 states are fixed by the protocol.

`rustbgpd-fsm 0.3.1` keeps its public API backward-compatible and pairs with
`rustbgpd-wire 0.16.0`. `PeerConfig` gains `min_hold_time: Option<u16>` and
`required_families: Vec<(Afi, Safi)>`; because `PeerConfig` is
`#[non_exhaustive]`, external construction goes through `PeerConfig::new` and
is unaffected by the new fields. Negotiation behavior also carries conformance
fixes: the last duplicate Graceful Restart capability wins, and invalid OPEN
identities (AS 0, or the local router ID on iBGP) are rejected. The paired wire
0.16.0 API is additive too, but its **decode acceptance changed in six places**
— see the "0.16.0 compatibility note" in the `rustbgpd-wire` README, since the
FSM surfaces wire decode results to its callers.

## Key types

- **`Session`** — the state machine: `handle_event(&mut self, Event) -> Vec<Action>` (state is mutated in place on `&mut self`)
- **`SessionState`** — `Idle`, `Connect`, `Active`, `OpenSent`, `OpenConfirm`, `Established`
- **`Event`** — `ManualStart`, `TcpConnectionConfirmed`, `BgpOpen`, `KeepAliveTimerExpires`, etc.
- **`Action`** — `SendOpen`, `SendKeepalive`, `SendNotification`, `StartTimer`, `StopTimer`, etc.
- **`NegotiatedSession`** — post-OPEN capabilities: families, Add-Path modes,
  `peer_paths_limits` / `effective_add_path_send_limits`, GR state, extended
  message support
- **`PeerConfig::paths_limit_receive_max`** — the preferred per-family receive
  limit, defaulting to `0` (disabled); `paths_limit_capabilities()` advertises
  it only when Add-Path receive is enabled
- **`PeerConfig::min_hold_time`** — minimum hold time accepted from the peer
  (`Option<u16>`, default `None`); when configured, an OPEN proposing a lower
  or zero hold time is rejected with Unacceptable Hold Time
- **`PeerConfig::required_families`** — configured families whose negotiation
  is mandatory (`Vec<(Afi, Safi)>`, default empty); an OPEN missing any of
  them is rejected with Unsupported Capability, and an empty list preserves
  RFC 4760 partial-intersection behavior
- **`graceful_restart_preserves_family`** — rustbgpd's implementation-support
  allowlist for families whose FSM/RIB lifecycle can retain GR/LLGR-stale routes

## License

MIT OR Apache-2.0
