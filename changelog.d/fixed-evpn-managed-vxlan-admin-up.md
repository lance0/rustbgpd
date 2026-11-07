### Fixed

- A managed fixed-VNI VXLAN under `[managed_netdevs]` is now created
  administratively up. It was created down, so the kernel dropped every frame
  for its remote FDB rows while the instance reported `Ready` and the link
  `owned-safe`. L2VNI readiness now requires the bridge and the selected VXLAN
  member to be administratively up, and a down managed link reports
  `owned-unsafe`. The next reconcile pass raises a down managed bridge,
  fixed-VNI or SVD VXLAN, VLAN upper, VRF, or L3VXLAN that carries exactly its
  stamp and matching protected attributes. See
  [managed netdevs](../docs/reference/configuration.md#managed_netdevs).
