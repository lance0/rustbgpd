### Changed

- Under a `RUST_LOG` quieter than `info` (`warn` or `error`), a session's
  events now carry the session's `peer` span fields, such as `peer_addr`,
  `remote_asn`, `peer_group` and an interface-only neighbor's `peer`
  label. This also holds for events a per-peer `log_level` enables on a
  session that was already running when a reload set the level.
  **Operator-visible:** with `warn` or `error`, warn and error events from
  inside a session gain the JSON `span`/`spans` objects and the text
  `peer{…}:` prefix that `info` output already had. Output under the
  default `info` is unchanged.
