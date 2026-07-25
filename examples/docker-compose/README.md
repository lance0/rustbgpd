# Docker Compose Quick Start

Spins up rustbgpd (AS 65001) peered with FRR (AS 65002) over a shared
bridge network. FRR advertises 4 IPv4 and 3 IPv6 sample prefixes.

## Start

```bash
docker compose up -d
```

First run builds the rustbgpd image (~60s). Sessions establish within seconds.
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

## Change it without restarting

Runtime mutations are persisted back to the config file, so they survive a
restart:

```bash
docker compose exec rustbgpd rbgp -s http://127.0.0.1:50051 \
  neighbor 10.99.0.30 add --remote-as 65003
docker compose exec rustbgpd cat /var/lib/rustbgpd/config.toml
```

`rustbgpd.toml` in this directory is a **template**. The daemon copies it into
its writable state volume on first start and runs from
`/var/lib/rustbgpd/config.toml` — a read-only bind mount cannot accept the
temp-file + rename write that config persistence uses, and every mutating
command would fail. Edit the template and `docker compose down -v` to start
over from it.

## Stop

```bash
docker compose down       # keeps runtime config edits
docker compose down -v    # discards them, next start reseeds from the template
```
