### Fixed

- Keep rebuilt peer-group sessions provisional until configuration persistence
  and configured-owner publication settle. Clean compensation restores admission
  without advancing retained-history ownership; ambiguous acknowledgements remain
  fenced. Runtime dampening enablement remains rejected.
