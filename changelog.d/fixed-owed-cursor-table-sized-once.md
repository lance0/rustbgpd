### Fixed

- A receiver that walks a VPNv4, VPNv6, labeled-unicast or EVPN family
  through the row cursor into its own Adj-RIB-Out (after an RFC 4724
  selection release, for example) now has that table sized once, at the
  first step that adds routes while the table holds at most 2,048 routes.
  Before, each 1,024-key step reserved only its own rows, so the table's
  hash indexes doubled again and again during the walk, and every receiver
  walking the same list doubled in the same steps. The freed tables stayed
  resident in the allocator while paused receivers kept the daemon idle,
  which raised peak memory when many private VPN receivers were rebuilt at
  once. The size is the routes and keys that first step added per key it
  read, times the keys still ahead of the receiver's cursors, capped by
  the family's Loc-RIB, so a receiver whose export policy or RT-Constrain
  membership accepts a fraction of the table gets a table sized to that
  fraction. A step that adds nothing reserves nothing, and a table that
  already holds more than 2,048 routes is not resized this way. Unicast,
  whose table is sized from the Loc-RIB when it is created, and VPN owned
  by an update group are unchanged.
