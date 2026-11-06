### Fixed

- A managed fixed-VNI VXLAN under `[managed_netdevs]` is now created
  administratively up. It was created down, so the kernel dropped every frame
  for its remote FDB rows while the instance reported `Ready` and the link
  `owned-safe`. L2VNI readiness now requires the bridge and the selected VXLAN
  member to be administratively up, a down managed bridge or VXLAN reports
  `owned-unsafe`, and the next reconcile pass raises one that carries exactly
  its stamp and matching protected attributes. See
  [managed netdevs](../docs/reference/configuration.md#managed_netdevs).
