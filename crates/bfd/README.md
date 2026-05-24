# rustbgpd-bfd

RFC 5880 BFD (Bidirectional Forwarding Detection) control-packet codec and a
single-hop **asynchronous** session state machine — pure and sans-IO, in the
same spirit as `rustbgpd-fsm`: the state machine consumes packet/timer **events**
and produces packet/timer/state-change **actions**. It never reads a clock, opens
a socket, or spawns a task; the daemon actor owns the real I/O, timers, and
transmit jitter.

## Scope

- **Single-hop asynchronous mode** (RFC 5880 + RFC 5881).
- **Out of scope:** multihop (RFC 5883), echo mode, demand mode, and
  authentication. The Multipoint (`M`) bit is rejected at decode; packets with
  the Authentication (`A`) bit are decoded structurally and discarded by the
  session (no auth is ever negotiated).

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
| RFC 5881 | Single-hop encapsulation context (UDP/3784, TTL/Hop-Limit 255). The TTL check and the sockets themselves live in the daemon actor, not this crate. |

## Design

Time is an **input**, never read internally: the session emits
`Action::StartTimer { kind, interval_us }` and the actor arms the real timer;
when it fires the actor feeds back `Event::TxTimerExpires` /
`Event::DetectTimerExpires`. This keeps the whole state machine deterministic and
unit-testable without a clock or a socket.
