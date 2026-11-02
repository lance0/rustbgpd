### Upgrade notes

- **`.rpol` set names must be unique across kinds.** A policy file that
  defines, for example, an `asn-set customers` and a `community-set
  customers` no longer loads, and with `rbgp policy check` or
  `rustbgpd --check` the error names both definitions. Rename one of them
  and update its `in` references.
