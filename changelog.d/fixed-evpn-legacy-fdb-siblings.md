### Fixed

- Legacy unscoped EVPN remote-MAC FDB programming checks foreign VLAN
  siblings before changing the bridge entry, including a static row present
  only on the port's PVID. A conflicting sibling blocks programming or
  removal until the operator clears it; explicitly configured bridge VLANs
  retain their own scope.
