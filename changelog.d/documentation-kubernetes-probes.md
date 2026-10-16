### Documentation

- The deployment guide now recommends Kubernetes startup, readiness and
  liveness probe settings: readiness on `/readyz` with the Kubernetes
  defaults, and liveness either on `/readyz` with a tolerance matching the
  systemd watchdog or on `/livez`, which checks no actors and does not
  restart a deadlocked RIB. See
  [Kubernetes probes](../docs/how-to/deployment.md#kubernetes-probes).
