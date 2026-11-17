### Changed

- The RIB's per-peer outbound credit, which bounds the private-family
  updates queued for receivers that are not reading, is now charged in
  estimated bytes instead of rows. The daemon divides 2 GiB among every
  registered outbound peer, from 2 MiB to 256 MiB each. The previous limit of
  16,777,216 rows was sized at an assumed 121 bytes a row; a paused-reader
  EVPN shape measured about 290 bytes a row, so stalled receivers could hold
  about 4.9 GB before the credit refused them. A new gauge,
  `bgp_rib_outbound_credit_bytes`, reports the credit in use; see the
  [metrics reference](../docs/reference/operations.md).
