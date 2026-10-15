### Fixed

- VPN group staging and EVPN recovery-refusal paths now service dedicated
  readiness probes while retiring temporary export state. Ordinary reads and
  mutations remain fenced, and existing readiness deadlines are unchanged.
