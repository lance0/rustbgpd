### Upgrade notes

- `.rpol` reserves some names that a policy parameter or set could
  previously take. A file that uses one now fails `rbgp policy check`,
  `rustbgpd --check` and a reload, with a diagnostic naming the
  collision. Rename the parameter or set. The reserved names are:
  - for parameters, an enum value of `route.rpki`, `route.aspa`,
    `route.route-type` or `route.family` (such as `valid`, `internal`,
    `ipv4-unicast`);
  - for parameters, the `prepend as` operands `origin` and `path-first`.
    A `u32` parameter of either name used to mean its argument in
    `prepend as origin`; the name now always means the operand;
  - for parameters and for prefix-sets, community-sets, asn-sets and
    datasets, a well-known community name: `NO_EXPORT`, `NO_ADVERTISE`,
    `NO_EXPORT_SUBCONFED`, `BLACKHOLE`, `GRACEFUL_SHUTDOWN`, `OV_VALID`,
    `OV_NOT_FOUND`, `OV_INVALID`.

  With every name read one way, an argument can no longer reach a
  position that reads it as something else. No `.rpol` file in this
  repository or its documentation used a reserved name. See
  [Parameters](../docs/reference/rpol-language.md#parameters).
