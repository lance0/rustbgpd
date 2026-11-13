# ADR-0147: Management servers restart in place

**Status:** Accepted
**Date:** 2026-11-13
**Supersedes:** [ADR-0022](0022-grpc-server-supervision.md), and the later
decision to fail-stop on an unexpected metrics/readiness server exit.

## Context

ADR-0022 made an unexpected gRPC server exit a shutdown trigger: an API-first
daemon without its API should exit so a process supervisor restarts it. The
same rule was later applied to the metrics/readiness HTTP server, so that the
daemon would not run without `/metrics`, `/readyz` and `/livez`.

Both rules end every BGP session to recover a management endpoint. A route
server or route reflector that drops all its sessions withdraws every route
it distributes, and its peers reconverge twice: once on the exit and once on
the restart. The fault that triggered it, a listener socket error or a panic
in a request handler, says nothing about whether routing state is correct.

ADR-0022 rejected an in-place restart for its complexity: backoff, re-binding
the port, and state recovery. In the code as it stands the cost is small.
The gRPC server holds no state of its own: every service is built from
cloneable handles to the actors, and `serve` spawns nothing that outlives it.
The metrics/readiness server is stateless as well.

## Decision

A management-plane failure does not end BGP. The daemon restarts the failed
server in place and keeps restarting it for as long as it takes.

1. **Both servers are supervised by a restart loop.** A run that ends before
   the daemon asked it to stop is an unexpected exit. It is logged at ERROR,
   counted in `bgp_management_server_crashes_total{server}` (`metrics` or
   `grpc`), and followed by a restart after a backoff of 100 ms doubling to
   10 seconds. A run that lasted 60 seconds resets the backoff. There is no
   restart budget and no exit: a server that never comes back leaves the
   daemon running BGP with that server down, one ERROR line per attempt.

2. **The 10 second cap is chosen against the documented Kubernetes liveness
   probe** (three consecutive failures, 10 seconds apart), so one restart gap
   does not get the daemon killed for the fault this decision is meant to
   survive.

3. **Startup is unchanged.** A configured listener that cannot bind or start
   at startup still fails startup with exit 1. Only a server that started
   once is restarted.

4. **Sockets.** The metrics/readiness supervisor keeps the bound socket and
   each run serves a duplicate, so the port stays bound and the kernel
   backlog holds connections during a restart. If the accept loop itself
   reported the socket unusable, the socket is closed and the address bound
   again. The gRPC listeners bind inside `serve`, so each run binds the
   configured TCP addresses and Unix socket paths again; all listeners
   restart together, because `serve` already stops the others when one
   fails. A bind that fails on restart is a failed start and is retried.

   The gRPC sockets are not kept across runs. A gRPC run ends on its own
   when a listening socket reports itself unusable, and that socket has to
   be replaced whatever the supervisor holds; a panic in a request handler
   ends only its connection, not the run. Keeping the sockets would
   therefore help only a panic in the listener task itself, and would need
   `serve` to take pre-bound listeners and to give up ownership of the Unix
   socket cleanup that today removes the path under the directory lock when
   a listener ends. During the gap an operator sees: TCP connections
   refused; the Unix socket path absent, since the ending run removes it and
   the restart creates it again; and, if another process binds the TCP port
   meanwhile, restarts that fail and are retried at most 10 seconds apart
   with `/readyz` red until the port is free.

5. **Readiness.** While the gRPC server is down, `/readyz` answers 503
   `not ready: gRPC server is restarting`: the mutation path is unavailable.
   It clears when the restarted server reports every listener started. The
   metrics/readiness server cannot report its own absence; while it is down
   the signal is the failed probe or scrape, and the counter afterwards.
   Liveness, the systemd watchdog and `READY=1` follow the core actors and do
   not treat a restarting management server as a failure.

6. **In-flight requests.** A gRPC run that ends stops accepting. Connections
   it already accepted are told to finish and a request in flight on one
   runs to its own answer; a caller whose connection dies gets a transport
   error. Owned runtime-config mutations are shielded from their caller
   ([ADR-0080](0080-cancellation-shielded-runtime-applies.md)) and settle or
   fence under the settlement watchdog
   ([ADR-0127](0127-config-transaction-settlement-watchdog.md)) regardless.
   No caller is told of a success that did not settle.

7. **Shutdown.** No restart begins once coordinated shutdown has started. A
   server that ends during shutdown is counted and left down, and does not
   change the exit code.

8. **Core components still fail-stop.** The RIB manager, the peer manager,
   the BGP listener and accept-forwarding tasks, the RPKI subsystem and the
   injection lease expiry task hold or guard routing state. Their unexpected
   exit still runs coordinated shutdown and exits 1.

## Consequences

**Positive:**
- A management-plane fault no longer withdraws routes or resets sessions.
- A crash is visible as a counter, an alert and an ERROR line instead of a
  process restart.

**Negative:**
- A daemon whose gRPC server cannot be restarted keeps running BGP while it
  cannot be managed through the API. Readiness stays red and the
  counter keeps rising; the operator decides when to restart the process.
  SIGTERM still stops it cleanly.
- During a gRPC restart the configured TCP ports and Unix socket paths are
  unbound for the length of the backoff.
- Monitoring that counted `Restart=on-failure` restarts for these two
  servers no longer sees them.

**Neutral:**
- `ExitCode 1` remains the component-failure exit for the core components
  and for startup failures.
- If a supervisor task itself ends, which is a defect, the daemon logs it at
  ERROR and keeps running with that server down.
