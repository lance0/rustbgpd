### Changed

- Outbound Add-Path path IDs for unicast now stay with a path while it is
  sent, instead of following rank order. A new path takes the lowest free
  ID, and rank decides only which paths fit `send_max`. A rank change no
  longer re-announces every path below it. Received paths keep their
  source peer's IDs; when one peer contributes several paths and one
  leaves, a survivor may still move to that peer's lowest ID.
  **Operator-visible:** advertised-route readback and best-path explain
  show these IDs, so path ID 1 is no longer always the best path.
