### Removed

- Removed `rustbgpd --migrate-config downgrade-v0.64` and its `--validator`
  option. To roll back to v0.64.0, restore a config that release accepts or
  use the v0.83.0 offline tool to convert the RFC 8212 posture. See the
  [rollback procedure](../docs/how-to/deployment.md#rollback).
