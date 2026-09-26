### Fixed

- Preserve each EVPN MAC's primary destination when MACs sharing a Linux
  nexthop-group key disagree on members or standby. Conflicting MACs use
  individual destination rows, with shared-group forwarding restored when
  their intent agrees again. Foreign kernel rows that block a MAC's programming
  do not force otherwise compatible MACs out of their shared group.
