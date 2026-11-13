### Fixed

- Removing the `.deb` or `.rpm` package now stops and disables `rustbgpd`
  and every `rustbgpd@` instance before deleting the binaries, so
  `ExecStopPost` still releases EVPN core-isolation links. Previously the
  daemon kept peering with its binary and unit deleted. An upgrade still
  leaves a running daemon alone; its notice now says a restart is
  required to load the new binary, instead of repeating the fresh-install
  text. `/var/lib/rustbgpd` is kept. See
  [Debian / RPM packages](../docs/how-to/deployment.md#debian--rpm-packages).
