### Fixed

- Reconcile managed SVD VXLAN VLAN and tunnel bindings during startup adoption
  and repair, removing stale bindings and allowing VLAN-to-VNI re-keying while
  preserving foreign ports and unrelated bridge VLANs.
