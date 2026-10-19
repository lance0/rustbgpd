### Fixed

- A policy chain composed from several `.rpol` units could reference more
  than the 16 datasets one evaluation pins. Every probe of a dataset past
  the 16th failed closed, so routes reaching that term were denied with a
  `dataset-unpinned` evaluation error even when the guard permitted them.
  Config load and reload now refuse such a chain, naming the chain member
  and the dataset count; see
  [External policy datasets](../docs/reference/configuration.md#external-policy-datasets-policydatasets).
