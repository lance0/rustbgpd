
> **Release framing — why this is v0.60.0.** This release marks the route-server stabilization line, a deliberate milestone jump from v0.51.0. Every finding from an external release review is closed and the flagship receipts are re-validated at this tip (reload stall p50 0.44–0.92 s, completion 1.50–2.12 s at 700 clients × 400,400 routes). A differential interop lab drives BIRD 2 (configured by real arouteserver 1.23.2) and rustbgpd (configured by `rs-config-render` from the same site data) to 65/65 identical accept/reject verdicts, and the renderer now ingests real `template-context` output directly. RFC 1997 and RFC 7606 semantics are complete, the update-group performance arc lands end to end, jemalloc becomes the default allocator, and the `rustbgpd-wire` 0.15.0 / `rustbgpd-fsm` 0.3.0 breaking cut ships in one release.

### Highlights

**Route-server correctness and policy**
