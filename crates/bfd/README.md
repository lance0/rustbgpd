# rustbgpd-bfd

RFC 5880 BFD (Bidirectional Forwarding Detection) control-packet codec and a
**asynchronous** session state machine — pure and sans-IO, in the
same spirit as `rustbgpd-fsm`: the state machine consumes packet/timer **events**
and produces packet/timer/state-change **actions**. It never reads a clock, opens
a socket, or spawns a task; the daemon actor owns the real I/O, timers, and
transmit jitter.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Scope

- **Asynchronous mode** (RFC 5880). Encapsulation is not this crate's
  concern: the daemon actor runs the same state machine for single-hop
  (RFC 5881, UDP/3784) and multihop (RFC 5883, UDP/4784) sessions.
- **Out of scope:** echo mode, demand mode, and authentication. The Multipoint
  (`M`) bit is rejected at decode; packets with the Authentication (`A`) bit
  are decoded structurally and discarded by the session (no auth is ever
  negotiated).

## Key types

- `ControlPacket` — encode/decode the 24-byte RFC 5880 §4.1 mandatory section
  (`ControlPacket::encode` / `ControlPacket::decode`). Interval fields are in
  **microseconds**.
- `Diagnostic` — the 5-bit diagnostic code.
- `SessionState` — `AdminDown` / `Down` / `Init` / `Up`.
- `Session` / `SessionConfig` — the sans-IO state machine
  (`Session::new`, `Session::handle`, `Session::administratively_down`).
- `Event` / `Action` / `TimerKind` — the machine's inputs and outputs.
- `DiscriminatorAllocator` — unique, non-zero local discriminators.

## RFC references

| RFC | Coverage |
|-----|----------|
| RFC 5880 | Control-packet format (§4.1) and the async session state machine (§6.8), including the slow-while-not-Up transmit floor (§6.8.3), detection time (§6.8.4), reception/FSM (§6.8.6), and AdminDown teardown (§6.8.16). |
| RFC 5881 / RFC 5883 | Single-hop (UDP/3784) and multihop (UDP/4784) encapsulation context. Both transmit with TTL/Hop-Limit 255; multihop has no receive minimum-TTL knob. The sockets and TTL rules live in the daemon actor. |
| RFC 5882 | BFD-client/BGP coupling (§3.2, §4.1/§4.2): `Session::remote_admin_down()` distinguishes a peer's administrative disable from a genuine liveness failure. Cause-only flips emit `Action::StateChanged` even when the local state remains `Down`, so callers can permit BGP during remote `AdminDown` without hiding a later remote `Down` or detection timeout. |

## Design

Time is an **input**, never read internally: the session emits
`Action::StartTimer { kind, interval_us }` and the actor arms the real timer;
when it fires the actor feeds back `Event::TxTimerExpires` /
`Event::DetectTimerExpires`. This keeps the whole state machine deterministic and
unit-testable without a clock or a socket.

## License

MIT OR Apache-2.0
