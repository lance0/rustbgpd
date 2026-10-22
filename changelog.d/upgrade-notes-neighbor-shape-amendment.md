### Upgrade notes

- The config schema's `Neighbor` shape changes, an amendment to the pinned
  pre-v1 stable-surface inventory; the inventory is frozen at the v1.0 tag.
  `address` is no longer in the schema's `required` set (it may be omitted
  only together with `interface`), and `remote_asn` changes type from an
  integer to an integer or one of the strings `"external"` and `"internal"`.
  Existing configurations stay valid and behave identically. Tools that
  validate configs against
  [the published schema](../docs/reference/rustbgpd.schema.json), or that
  read `remote_asn` as an integer, need to accept the new forms.
