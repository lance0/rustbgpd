### Documentation

- Refresh the [BGP implementation comparison](../docs/explanation/comparison.md)
  and [GoBGP parity page](../docs/explanation/gobgp-parity.md) against their
  pinned releases: GoBGP v4.10.0 applies TCP-AO keychains to peer sockets,
  BIRD 3.3.3 does not implement RT-Constrain, conditional advertisement is
  listed as a shipped alpha feature, and RT-Constrain matching is described
  as Route Target prefix matching independent of the membership origin AS.
  The comparison, IXP evaluation and performance index now cite the
  2026-10-06 BIRD 3.3.3 IRR comparison and the v0.74.0 and v0.75.0 flagship
  soak passes.
