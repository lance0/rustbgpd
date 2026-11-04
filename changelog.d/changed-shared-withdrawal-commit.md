### Changed

- Keep grouped unicast withdrawals shared through outbound commit, copying them
  only when a receiver's export gates change the payload.
- Represent empty shared withdrawal payloads without retaining an allocation.
