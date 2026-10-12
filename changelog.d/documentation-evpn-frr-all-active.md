### Documentation

- Document the FRR 10.7.1 requirements for a shared all-active Ethernet
  Segment: use `highest-preference` and give FRR the higher DF preference.
  Stock FRR on Linux does not filter BUM when it is non-DF, so with
  rustbgpd as DF the CE receives each BUM frame twice; this is a known
  limitation. A new interop receipt covers FRR-DF forwarding and carrier
  recovery, the rustbgpd-DF duplicate, and the default-modulo case.
