### Fixed

- The config JSON Schema rejected the BGP `role` values `"rs"` and
  `"rs-client"`, which the daemon accepts as aliases of `"route_server"` and
  `"route_server_client"`, so schema-validating editors flagged working
  configs. The schema now lists both spellings. The reference docs now present
  the snake_case names as canonical, since the daemon writes those names when
  it saves a config, and list the short forms as aliases.
  **Operator-visible:** `rustbgpd.schema.json` gains `"rs"` and `"rs-client"`
  in the role enum; accepted configs are unchanged. See the
  [configuration reference](../docs/reference/configuration.md).
