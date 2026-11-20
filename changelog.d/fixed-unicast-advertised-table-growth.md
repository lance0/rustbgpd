### Fixed

- A unicast advertised-route table moves far less memory when its prefix
  index grows. Each receiver's table and each update group's shared table
  indexes its prefixes in a trie whose cells sit in one vector that doubles
  by copying and cannot be reserved ahead. A cell was a 24-byte list of path
  IDs and route handles, so the doubling at 1,048,576 cells moved 24 MiB
  inside one insert, and every peer's updates waited behind it. A cell is
  now 4 bytes: the route's handle for a prefix advertised with one path, or
  the slot of a path list kept beside the table for a prefix advertised
  with several. The same doubling moves 4 MiB. The move still grows with
  the table: it is six times smaller, not bounded. The evidence is a work
  count in a unit test (1.2 million prefixes, no insert above 6 MiB), not a
  timing. How many cells a table needs depends on the order its prefixes
  arrive in, between about one and three per prefix. The trie's node
  vector, 16 bytes per slot, is unchanged and still doubles the same way:
  on a sparse prefix shape arriving in hash-like order it moves 8,388,608
  bytes in one insert, before and after this change.
  **Operator-visible:** the cell capacity of a single-path unicast table is
  one sixth of what it was, 8 MiB against 48 MiB at one million prefixes by
  the cell sizes. The whole prefix index, cells and nodes, went from 28.0
  to 8.0 MiB (3.5 times smaller) in a work count on 660,350 IPv4 prefixes
  of a real shape; neither figure is a daemon measurement. A prefix
  advertised with several Add-Path paths takes a 32-byte list slot beside
  its cell; lists of more than two paths allocate as before.
