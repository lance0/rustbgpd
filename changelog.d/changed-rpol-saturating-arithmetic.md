### Changed

- `.rpol` arithmetic saturates. `+`, `-` and `*` stop at 0 and 4294967295 in
  every value position instead of failing, so `set med route.med - 10` on a
  route with MED 4 sets 0, as in IOS-XR RPL, Junos and FRR, rather than
  denying the route. `clamp(x, lo, hi)` is `min(max(x, lo), hi)` and never
  fails. The divisor of `/` or `%` must be a non-zero constant or
  `max(e, k)` with a constant `k >= 1`, so division never fails at runtime.
  A literal-only expression that leaves u32 (`4294967295 + 1`) is still a
  compile error; an expression with a parameter folds with saturation, so an
  argument value never decides whether a policy loads. See
  [Saturating u32 value expressions](../docs/reference/rpol-language.md#saturating-u32-value-expressions).
