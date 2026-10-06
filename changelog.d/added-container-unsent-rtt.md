### Added

- The unsent-data threshold experiment can run isolated container RTT legs
  with daemon-only cgroup accounting, receiver-ingress delay and live TCP RTT
  evidence. The native namespace path now uses the same ingress shaping and
  rejects missing delay or dropped packets. Production defaults are unchanged.
