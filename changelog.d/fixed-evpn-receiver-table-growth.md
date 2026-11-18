### Fixed

- A receiver's advertised EVPN table no longer copies every stored route
  when it grows. The routes were stored inside the table's hash buckets,
  208 bytes each with the key, so the growth steps at 28,672, 57,344 and
  114,688 routes moved 6, 12 and 24 MB inside one insert. Every EVPN
  receiver holds about the same routes, so all of them took the same step
  inside one inbound UPDATE, and every peer's updates waited behind it.
  The routes now live in a slab that does not move them, and the table
  holds 68-byte entries that point into it and grows one sixteenth at a
  time: up to about 900,000 routes per receiver no single insert moves
  more than 2 MiB. Past that a growth step moves one sixteenth of the
  table's entries, 3.9 MB at 911,000 routes. The evidence is a work count
  in a unit test, not a timing.
  **Operator-visible:** memory per advertised EVPN route per receiver is
  lower for large tables, about 40 MB against 55 MB at 150,000 routes by
  the tables' sizes, not a daemon measurement. A receiver with more than
  8,192 EVPN routes reserves address space for 65,536 route slots (9.4 MB)
  at once; pages that hold no route are not resident. The order in which
  the routes of one table are walked was never specified and may differ.
