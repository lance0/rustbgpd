### Changed

- Prepare shared EVPN announcement encoding behind the existing dormant group
  ownership boundary. Clean identical incremental views can share payloads and
  encoded UPDATEs; differing views and recovery feeds retain private encoding.
  Production EVPN ownership remains disabled, with no new operator setting or
  scale claim.
