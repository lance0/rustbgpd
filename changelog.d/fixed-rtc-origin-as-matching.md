### Fixed

- RT-Constrain matches VPN and EVPN route targets independently of the
  membership origin AS, so peers can import targets administered by another
  AS. Partial RT prefixes remain supported; /32 covers every RT value,
  while only the default /0 admits routes with no RT.
