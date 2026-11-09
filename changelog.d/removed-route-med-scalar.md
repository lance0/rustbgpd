### Removed

- `Route` no longer carries the bare `med` scalar (field 8, now reserved by
  number and name). It reported a route without a MULTI_EXIT_DISC attribute
  as `0`, the same value as an explicit MED of 0. The optional `med_attr`
  field, present since 0.51.0, remains the MED report on received, best,
  advertised and explain route rows. `rbgp` already read only `med_attr`, so
  its output does not change.
