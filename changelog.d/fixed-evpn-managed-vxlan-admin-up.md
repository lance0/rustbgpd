### Fixed

- A managed fixed-VNI VXLAN under `[managed_netdevs]` is now created
  administratively up. It was created down, so the kernel dropped every frame
  for its remote FDB rows while the instance reported `Ready` and the link
  `owned-safe`. L2VNI readiness now requires the bridge and the selected VXLAN
  member to be administratively up, and a down managed bridge, fixed-VNI or
  SVD VXLAN, or VLAN upper reports `owned-unsafe`. The next reconcile pass
  raises one that carries exactly its stamp and matching protected attributes.
  A down managed VRF or L3VXLAN is reported until it is raised out of band. See
  [managed netdevs](../docs/reference/configuration.md#managed_netdevs).
