FROM rust:1.93-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/rustbgpd /usr/local/bin/rustbgpd
COPY tests/interop/scripts/start-rustbgpd.sh /usr/local/bin/start-rustbgpd.sh

CMD ["sleep", "infinity"]
