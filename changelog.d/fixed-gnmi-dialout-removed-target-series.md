### Fixed

- Removing a gNMI dial-out target on reload now removes its
  `gnmi_dialout_queue_depth` and `gnmi_dialout_last_publish_timestamp_seconds`
  series for good. Previously, a response the transport was still sending when
  the target was removed could recreate those series. `/metrics` then exported
  a stale series for a target that no longer existed, until the daemon
  restarted.
