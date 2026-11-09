### Upgrade notes

- gRPC clients that read `Route.med` must read `Route.med_attr` instead: a
  set value is the route's MED, including an explicit `0`, and an absent
  value means the route carries no MED attribute. A client built against an
  older `rustbgpd.proto` that still reads `med` now sees the proto3 default
  `0` for every route.
