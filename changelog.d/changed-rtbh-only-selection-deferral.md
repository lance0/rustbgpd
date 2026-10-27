### Changed

- Limit the unicast Graceful Restart selection-deferral bypass to locally
  injected IPv4 `/32`, IPv6 `/128` or BLACKHOLE `65535:666` routes. Untagged
  defaults, aggregates and other non-host injections wait with received
  candidates. Removing BLACKHOLE from a non-host injection withdraws its old
  advertisement without exposing a received fallback before selection resumes.
  The existing injected FlowSpec exemption is unchanged. See the
  [injection contract](../docs/reference/api.md#unicast-injection-contract).
