### Fixed

- A receiver that walks a VPNv4, VPNv6, labeled-unicast or EVPN family
  through the row cursor into its own Adj-RIB-Out (after an RFC 4724
  selection release, for example) now has that table sized once, while it
  holds at most 2,048 routes. Before, each 1,024-key step reserved only its
  own rows, so the table's hash indexes doubled again and again during the
  walk, and every receiver walking the same list doubled in the same steps.
  The freed tables stayed resident in the allocator while paused receivers
  kept the daemon idle, which raised peak memory when many private VPN
  receivers were rebuilt at once. The size comes from each address
  family's own sample once the walk's cursor steps have read at least 512
  of its keys and committed at least 256 of its routes: the routes those
  steps committed per key they read, at most the receiver's paths per key
  (one for an Add-Path receiver that sends every path), times its keys
  still ahead. Routes that reach the table any other way (held before the
  walk, restaged by an RT-Constrain membership change, or sent from the
  receiver's own owed keys) do not count, nor do keys logged again or
  withdrawn ahead of the cursor. A receiver whose export policy or
  RT-Constrain membership accepts a fraction of the table therefore gets a
  table sized to that fraction, and VPNv4 and VPNv6 (or the two labeled
  families) sharing one table are each sized by their own acceptance. A
  family without such a sample adds nothing, and its table grows step by
  step as before; a table that already holds more than 2,048 routes is not
  resized this way. Unicast, whose table is sized from the Loc-RIB when it
  is created, and VPN owned by an update group are unchanged.
