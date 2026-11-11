### Security

- Update the locked `rustix` dependency to 1.1.6 for RUSTSEC-2026-0486,
  fixing unsound extended-attribute buffer handling. The separate 0.38 series
  is unaffected and remains unchanged.
