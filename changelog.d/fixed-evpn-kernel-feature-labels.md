### Fixed

- Correct EVPN Linux kernel feature labels and maintained test guidance:
  externally learned bridge/VXLAN FDB programming and broadcast flood control
  arrived in upstream Linux 4.12; per-port VLAN database dumps in 5.6 and
  their tunnel options in 5.7. Error classification and dataplane behavior
  are unchanged; these feature floors do not qualify older kernel releases.
