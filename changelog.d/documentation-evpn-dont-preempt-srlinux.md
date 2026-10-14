### Documentation

- Add the M123 hosted interop leg and its [SR Linux 25.10.1 receipt](../docs/artifacts/interop/m123-evpn-dont-preempt-20261013/README.md)
  for RFC 9785 Don't-Preempt on a two-PE all-active Ethernet Segment behind a
  Linux LACP CE: a restarted rustbgpd inherits SR Linux's preference with DP=0
  and leaves it DF, SR Linux recovering from a CE-link failure inherits
  rustbgpd's preference, and the survivor of a reference-PE withdrawal
  restores its administrative values. Lowest-Preference, more than two PEs,
  SR Linux node restart and forwarding remain outside this receipt.
