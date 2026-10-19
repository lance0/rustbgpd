### Changed

- A dirty update-group member that holds an admitted-key recovery proof now
  resyncs with fewer full passes over that proof: the commit reuses the
  pre-send reservation, retention checks skip unused entry lookups, proof keys
  are no longer copied into a temporary prior or the resync's prefix scope
  when the existing fallback already covers a refusal, and proof lookups
  compare addresses as integers. Wire output, withdrawal duties and recovery
  memory are unchanged; full-table mass-dirty recovery spends less RIB-actor
  time per proof-backed member.
