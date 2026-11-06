### Fixed

- A forced outbound resync that was still waiting on a full outbound channel
  (for example after a graceful-shutdown toggle or an ORF IMMEDIATE) now ends
  with the session that owed it. Before this fix, if that session ended through
  graceful restart, a replacement session, or a collision failback, the new
  session received its full initial table and then the whole table again on
  the next distribution pass.
