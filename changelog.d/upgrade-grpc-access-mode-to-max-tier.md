### Upgrade notes

- Replace each gRPC listener `access_mode` before upgrading; the key no
  longer loads. With `access_mode = "read_only"`, delete it and set
  `max_tier` to the stricter of `"sensitive_read"` and any `max_tier` the
  listener already has, so `max_tier = "read"` stays `"read"`. With
  `access_mode = "read_write"`, delete it and keep any existing `max_tier`,
  or leave `max_tier` unset to serve every tier. This keeps each listener's
  effective ceiling unchanged. Scripts and benchmark or lab harnesses outside
  this repository that generate listener tables need the same edit. Run
  `rustbgpd --check` on the new config before restarting.
