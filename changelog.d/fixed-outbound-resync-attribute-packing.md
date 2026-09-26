### Fixed

- An outbound resync or table replay now packs routes into UPDATE messages by
  attribute value, not by the allocation that carried them. When an export
  policy modified attributes and the source peer sent a few prefixes per
  UPDATE, a replay emitted about one UPDATE per original inbound message. A
  large enough replay overran the per-peer writer queue and tore a healthy
  session down with Cease/Out-of-Resources.
  **Operator-visible:** such peers now receive the same routes in far fewer
  UPDATE messages, and the teardown no longer occurs for this cause.
