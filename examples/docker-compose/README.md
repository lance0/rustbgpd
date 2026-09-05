# Docker Compose Quick Start

Spins up rustbgpd (AS 65001) peered with FRR (AS 65002) over a shared
bridge network. FRR advertises 4 IPv4 and 3 IPv6 sample prefixes.

## Start

Run these commands from `examples/docker-compose/`.

```bash
docker compose up -d --build
```

`--build` asks Compose to build from the current checkout before startup.
Without it, Compose may reuse an older `docker-compose-rustbgpd` image already
on the host. Build time depends on the machine and available cache; wait for
the neighbor to reach `Established` before continuing.

The committed bearer token is intentionally public and test-only: it keeps the
quick-start runnable while demonstrating tier authorization. Replace this
entire credential arrangement in any real deployment.

## Try it

```bash
# Inside the container
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 neighbor
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 rib
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 top

# From the host (gRPC is forwarded to localhost:50051)
export RUSTBGPD_TOKEN_FILE="$PWD/../../tests/fixtures/grpc-test-only-operator.token"
cargo run -p rustbgpctl --bin rbgp -- -s http://127.0.0.1:50051 neighbor
cargo run -p rustbgpctl --bin rbgp -- -s http://127.0.0.1:50051 top
```

## Break, explain, restore

Try a missing-policy failure in this local demo. First verify that FRR's
`192.168.1.0/24` is selected:

```bash
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 \
  rib --prefix 192.168.1.0/24 --explain
```

Clear the import chain. The demo enables RFC 8212 enforcement, so an eBGP
session without an explicit import policy rejects incoming routes:

```bash
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 \
  policy chain clear-import
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 neighbor
```

After the update settles, the neighbor remains `Established` with `Rx Pfx`
zero. Find where the routes went:

```bash
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 \
  rib received 10.99.0.20 --rejected
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 \
  policy explain --neighbor 10.99.0.20 --prefix 192.168.1.0/24
curl --fail --silent http://127.0.0.1:9179/metrics \
  | grep '^bgp_rfc8212_missing_import_policy'
```

The rejected routes show `policy_reject` with detail
`rfc8212_missing_import_policy`. Import explain names the same policy and its
`default-action deny`; the metric is `1`. The session is healthy, but its
routes cannot pass the missing import policy.

Restore the demo's permit policy and verify that the prefix returns:

```bash
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 \
  policy chain set-import lab-permit-all-import
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 \
  rib --prefix 192.168.1.0/24 --explain
```

The prefix is selected from `10.99.0.20` again, and the missing-policy metric
returns to `0`. These chain changes persist, so complete the restore before
stopping if you want the next start to accept routes.

## Change it without restarting

Runtime mutations are persisted back to the config file, so they survive a
restart:

```bash
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 \
  neighbor 10.99.0.30 add --remote-asn 65003
docker compose exec rustbgpd cat /var/lib/rustbgpd/config.toml
```

`rustbgpd.toml` in this directory is a **template**. The service's start
command copies it into the writable state volume on first start (`cp -n`, see
`command:` in `docker-compose.yml`) and the daemon then runs from
`/var/lib/rustbgpd/config.toml` — a read-only bind mount cannot accept the
temp-file + rename write that config persistence uses, and every mutating
command would fail. The daemon itself has no template-seeding behavior, so a
port of this pattern to another supervisor has to carry the copy. Edit the
template and `docker compose down -v` to start over from it.

The service has a 32-minute stop grace so an explicit Compose stop does not
kill a runtime-config owner before its fixed 30-minute settlement watchdog.
There is deliberately no Compose restart policy: production supervisors
should choose their own bounded retry policy. A detected ambiguous mutation
turns readiness red, closes persisted-mutation admission, and exits 70 within
five seconds; a silent owner exits by 30 minutes plus five seconds.

## Stop

```bash
docker compose down       # keeps runtime config edits
docker compose down -v    # discards them, next start reseeds from the template
```
