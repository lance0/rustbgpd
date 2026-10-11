### Upgrade notes

- A `ListNeighbors` response that overlaps a configuration transaction can
  now arrive after `config reload complete` is logged. Its configuration
  fields describe the peer manager when the read was admitted, so arrival
  after reload completion does not mean the response reflects the new
  configuration.
