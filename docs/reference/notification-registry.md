# NOTIFICATION registry

Use this table to interpret BGP NOTIFICATION code/subcode pairs in session logs,
neighbor last errors, and lifecycle events.

The table follows the [IANA BGP error codes and subcodes registry][IANA], checked
2026-09-08. Descriptions preserve existing diagnostic labels where applicable;
FSM subcode 0 retains `Finite State Machine Error` for IANA's `Unspecified Error`.
Deprecated allocations remain labeled as deprecated. Description coverage does
not imply support for the associated protocol: codes 7 and 9 still use the
wire API's `NotificationCode::Unknown` variant, preserving numeric round trips.

Codes 4 and 9 have no defined subcodes, so subcode 0 follows [RFC 4271 §4.5][RFC4271].
Code 8 explicitly requires subcode 0 in [RFC 9687 §6][RFC9687]. Code 0 and subcode 0
under codes 6 and 7 are reserved. Other pairs absent from the table are unassigned
in this registry snapshot. Operator rendering uses `reserved(6/0)` or
`unassigned(6/42)` with the actual numbers, including a Hard Reset's inner pair.
The static wire `description()` API retains its `Unknown` / `Unknown Error Code`
fallback; callers should keep numeric values when rendering it.

The integration test reads every row and checks the exact description, then
checks that other pairs have no named description. Updating a documented row
requires a matching implementation. This is a maintained snapshot, not an
automatic check for new IANA allocations; review upstream before adding rows.

<!-- notification-descriptions:start -->
| Code | Subcode | Description | Status | Reference |
| --- | --- | --- | --- | --- |
| 1 | 0 | Message Header Error: Unspecific | active | [Errata4493][Errata4493] |
| 1 | 1 | Connection Not Synchronized | active | [RFC4271][RFC4271] |
| 1 | 2 | Bad Message Length | active | [RFC4271][RFC4271] |
| 1 | 3 | Bad Message Type | active | [RFC4271][RFC4271] |
| 2 | 0 | OPEN Message Error: Unspecific | active | [Errata4493][Errata4493] |
| 2 | 1 | Unsupported Version Number | active | [RFC4271][RFC4271] |
| 2 | 2 | Bad Peer AS | active | [RFC4271][RFC4271] |
| 2 | 3 | Bad BGP Identifier | active | [RFC4271][RFC4271] |
| 2 | 4 | Unsupported Optional Parameter | active | [RFC4271][RFC4271] |
| 2 | 5 | Deprecated OPEN Message Error Subcode 5 | deprecated | [RFC4271][RFC4271] |
| 2 | 6 | Unacceptable Hold Time | active | [RFC4271][RFC4271] |
| 2 | 7 | Unsupported Capability | active | [RFC5492][RFC5492] |
| 2 | 8 | Deprecated OPEN Message Error Subcode 8 | deprecated | [RFC9234][RFC9234] |
| 2 | 9 | Deprecated OPEN Message Error Subcode 9 | deprecated | [RFC9234][RFC9234] |
| 2 | 10 | Deprecated OPEN Message Error Subcode 10 | deprecated | [RFC9234][RFC9234] |
| 2 | 11 | Role Mismatch | active | [RFC9234][RFC9234] |
| 3 | 0 | UPDATE Message Error: Unspecific | active | [Errata4493][Errata4493] |
| 3 | 1 | Malformed Attribute List | active | [RFC4271][RFC4271] |
| 3 | 2 | Unrecognized Well-known Attribute | active | [RFC4271][RFC4271] |
| 3 | 3 | Missing Well-known Attribute | active | [RFC4271][RFC4271] |
| 3 | 4 | Attribute Flags Error | active | [RFC4271][RFC4271] |
| 3 | 5 | Attribute Length Error | active | [RFC4271][RFC4271] |
| 3 | 6 | Invalid ORIGIN Attribute | active | [RFC4271][RFC4271] |
| 3 | 7 | Deprecated UPDATE Message Error Subcode 7 | deprecated | [RFC4271][RFC4271] |
| 3 | 8 | Invalid NEXT_HOP Attribute | active | [RFC4271][RFC4271] |
| 3 | 9 | Optional Attribute Error | active | [RFC4271][RFC4271] |
| 3 | 10 | Invalid Network Field | active | [RFC4271][RFC4271] |
| 3 | 11 | Malformed AS_PATH | active | [RFC4271][RFC4271] |
| 4 | 0 | Hold Timer Expired | active | [RFC4271][RFC4271] |
| 5 | 0 | Finite State Machine Error | active | [RFC6608][RFC6608] |
| 5 | 1 | Receive Unexpected Message in OpenSent State | active | [RFC6608][RFC6608] |
| 5 | 2 | Receive Unexpected Message in OpenConfirm State | active | [RFC6608][RFC6608] |
| 5 | 3 | Receive Unexpected Message in Established State | active | [RFC6608][RFC6608] |
| 6 | 1 | Maximum Number of Prefixes Reached | active | [RFC4486][RFC4486] |
| 6 | 2 | Administrative Shutdown | active | [RFC4486][RFC4486], [RFC9003][RFC9003] |
| 6 | 3 | Peer De-configured | active | [RFC4486][RFC4486] |
| 6 | 4 | Administrative Reset | active | [RFC4486][RFC4486], [RFC9003][RFC9003] |
| 6 | 5 | Connection Rejected | active | [RFC4486][RFC4486] |
| 6 | 6 | Other Configuration Change | active | [RFC4486][RFC4486] |
| 6 | 7 | Connection Collision Resolution | active | [RFC4486][RFC4486] |
| 6 | 8 | Out of Resources | active | [RFC4486][RFC4486] |
| 6 | 9 | Hard Reset | active | [RFC8538][RFC8538] |
| 6 | 10 | BFD Down | active | [RFC9384][RFC9384] |
| 7 | 1 | Invalid Message Length | active | [RFC7313][RFC7313] |
| 8 | 0 | Send Hold Timer Expired | active | [RFC9687][RFC9687] |
| 9 | 0 | Loss of LSDB Synchronization | active | [RFC9815][RFC9815], [RFC4271][RFC4271] |
<!-- notification-descriptions:end -->

[IANA]: https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml
[Errata4493]: https://www.rfc-editor.org/errata/eid4493
[RFC4271]: https://www.rfc-editor.org/rfc/rfc4271
[RFC4486]: https://www.rfc-editor.org/rfc/rfc4486
[RFC5492]: https://www.rfc-editor.org/rfc/rfc5492
[RFC6608]: https://www.rfc-editor.org/rfc/rfc6608
[RFC7313]: https://www.rfc-editor.org/rfc/rfc7313
[RFC8538]: https://www.rfc-editor.org/rfc/rfc8538
[RFC9003]: https://www.rfc-editor.org/rfc/rfc9003
[RFC9234]: https://www.rfc-editor.org/rfc/rfc9234
[RFC9384]: https://www.rfc-editor.org/rfc/rfc9384
[RFC9687]: https://www.rfc-editor.org/rfc/rfc9687
[RFC9815]: https://www.rfc-editor.org/rfc/rfc9815
