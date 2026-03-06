# rustbgpd-fsm

Pure RFC 4271 BGP finite state machine. No I/O, no async runtime, no
sockets — just `(State, Event) -> (State, Vec<Action>)`.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Design

The FSM is intentionally isolated from all I/O concerns. The transport
layer feeds events in and executes the resulting actions. This makes the
FSM trivially testable and enables property-based testing of state
transitions.

All six RFC 4271 states are implemented: Idle, Connect, Active,
OpenSent, OpenConfirm, Established. Capability negotiation (4-octet AS,
multi-protocol, Add-Path, graceful restart, extended messages) is
handled during OPEN exchange.

## Key types

- **`Session`** — the state machine: `handle_event(Event) -> (State, Vec<Action>)`
- **`State`** — `Idle`, `Connect`, `Active`, `OpenSent`, `OpenConfirm`, `Established`
- **`Event`** — `ManualStart`, `TcpConnectionConfirmed`, `BgpOpen`, `KeepAliveTimerExpires`, etc.
- **`Action`** — `SendOpen`, `SendKeepalive`, `SendNotification`, `StartTimer`, `StopTimer`, etc.
- **`NegotiatedSession`** — post-OPEN capabilities: families, Add-Path modes, GR state, extended message support

## License

MIT OR Apache-2.0
