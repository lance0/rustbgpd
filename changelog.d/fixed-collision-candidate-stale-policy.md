### Fixed

- A session promoted from an inbound connection collision now starts with
  the neighbor's current import and export policy, graceful-shutdown setting
  and prefix limits. Previously it kept the values copied when the inbound
  connection was accepted. A policy or knob change made while that
  connection was pending was lost after promotion, and the neighbor was
  exported to and imported from under the old policy, even though the change
  had reported success.
