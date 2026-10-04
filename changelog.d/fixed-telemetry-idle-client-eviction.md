### Fixed

- Idle or slow-sending clients on the telemetry HTTP listener can no longer
  delay `/livez` and `/readyz` by holding connections for the 5 s request
  read timeout. While all 64 connections are in use, the listener closes the
  oldest connection that has not sent its request line within 250 ms of being
  accepted, so idle clients filling the budget delay a probe by about
  250 ms rather than 5 s.
  **Operator-visible:** a client that connects and then delays its request
  line can be disconnected without a reply while the listener is saturated.
