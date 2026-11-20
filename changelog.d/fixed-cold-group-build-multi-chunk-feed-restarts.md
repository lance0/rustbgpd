### Fixed

- A paced first-member update-group build no longer starts over repeatedly
  while another peer sends large UPDATEs. With Extended Message, one UPDATE
  can change 2,048 or more best routes; a steady stream of them changed
  routes faster than the build picked the changes up, so the build threw
  its partial table away and began again for as long as the stream lasted.
  The build now picks up changes on every one of its turns while more than
  2,048 are waiting, which matches the rate at which route input can change
  best routes.
  **Operator-visible:** a peer joining a RIB of at least 10,000 best routes
  as the first member of its update group, and peers waiting for the same
  group, no longer wait for such a stream to stop before they get their
  initial table and End-of-RIB. Their table still takes longer to arrive
  while the stream lasts, because most build turns then go to the changed
  routes. Other peers' input was not delayed, and still is not, with one
  exception. When such a build also holds an export-policy change with a
  session end waiting behind it, and the stream has left more than 2,048
  changes waiting on 64 of the build's turns, the RIB stops reading other
  peers' input until the build finishes, so that the session end does not
  wait for as long as the stream lasts. If the UPDATE being applied at that
  point has more than 2,048 routes, the build can still be thrown away once
  and is then built again with the input held. Before, the hold began only
  after the build had been thrown away at least once.
