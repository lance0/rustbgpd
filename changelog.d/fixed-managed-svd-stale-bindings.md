### Fixed

- Reconcile managed SVD VXLAN VLAN and tunnel bindings during startup adoption
  and repair, removing stale bindings and allowing VLAN-to-VNI re-keying while
  preserving foreign ports and unrelated bridge VLANs. Membership follows the
  configured bindings, so VLAN/VNI mappings added by hand on a managed SVD,
  and its default VLAN 1 port VLAN, are now removed.
- Recognize interior VLAN/VNI bindings in compressed kernel ranges when checking
  SVD readiness and selecting targets for FDB programming.
  Match raw ranges without expanding every VLAN per lookup, and reject malformed
  trailing inventory rows.
