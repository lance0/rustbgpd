### Changed

- Retire outbound prefix indexes using small batches of keys, preserving
  per-entry readiness checkpoints while reducing repeated trie traversal.
  A 400,400-prefix fixture used 62.4% fewer instructions and 47.0% fewer CPU
  cycles; end-to-end reload latency was not measured in this comparison.
