# Docker Compose Quick Start

Spins up rustbgpd (AS 65001) peered with FRR (AS 65002) over a shared
bridge network. FRR advertises 4 IPv4 and 3 IPv6 sample prefixes.

## Start

```bash
docker compose up -d
```

First run builds the rustbgpd image (~60s). Sessions establish within seconds.

## Try it

```bash
# Inside the container
docker compose exec rustbgpd rustbgpctl -s http://127.0.0.1:50051 neighbor
docker compose exec rustbgpd rustbgpctl -s http://127.0.0.1:50051 rib
docker compose exec rustbgpd rustbgpctl -s http://127.0.0.1:50051 top

# From the host (gRPC is forwarded to localhost:50051)
cargo run -p rustbgpctl -- -s http://127.0.0.1:50051 neighbor
cargo run -p rustbgpctl -- -s http://127.0.0.1:50051 top
```

## Stop

```bash
docker compose down
```
