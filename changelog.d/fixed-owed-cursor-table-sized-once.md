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
  steps committed per entry of the shared key list they passed, at most
  one route a key, times the entries still ahead of the cursor in the
  release's inventory. That
  inventory is logged in one pass in hash order, so the keys read first are
  a fair sample of the rest of it; keys that arrive in later passes come
  in arrival order (a source, VRF or Route Target at a time), so none of
  them is counted, and the table grows step by step for them as before.
  Routes that reach the table any other way (held before the walk, or
  sent from the receiver's own owed keys) do not count. The table is
  presized only when the release inventory's sample was taken with no
  change to the list or the receiver's acceptance; otherwise it grows as
  before. So a key logged into the list after the inventory (a
  re-announcement, withdrawal, relabel, best-path change or policy
  dataset re-evaluation), an RT-Constrain membership change, or a resync
  of the receiver before the estimate means the walk makes no estimate.
  A change after the estimate (a withdrawal, for example) leaves the
  reservation in place, as the whole-family send did. A receiver
  whose export policy or RT-Constrain membership accepts a fraction of
  the release's inventory therefore gets a table sized to that fraction
  of it, and VPNv4 and VPNv6
  (or the two labeled families) sharing one table are each sized by their
  own acceptance. An Add-Path receiver's route index is sized for one path
  a key and grows past it step by step; its key index is sized for the
  keys it accepts. A family without such a sample adds nothing, and a
  cursor that starts because a receiver's owed keys passed their byte cap
  makes no estimate. A table that already holds more than 2,048 routes is
  not resized this way. Unicast, whose table is sized from the Loc-RIB
  when it is created, and VPN owned by an update group are unchanged.
