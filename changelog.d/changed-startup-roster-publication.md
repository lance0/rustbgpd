### Changed

- Startup registers every configured neighbor in one peer-manager operation,
  so the policy-stats import roster is published once at startup instead of
  once per neighbor, which grew quadratically with the neighbor count.
  **Operator-visible:** during startup, before `/readyz` reports ready,
  `GetPolicyStats` returns `NOT_FOUND` for every configured neighbor until the
  whole set is registered, and a peer-manager read that arrives while
  registration runs waits for it, within its read deadline, instead of
  answering `NOT_FOUND` part-way. See the
  [API reference](../docs/reference/api.md).
