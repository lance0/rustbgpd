FROM rust:1.88-bookworm AS builder

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
COPY --from=builder /build/target/release/rustbgpctl /usr/local/bin/rustbgpctl
COPY tests/interop/scripts/start-rustbgpd.sh /usr/local/bin/start-rustbgpd.sh

RUN mkdir -p /var/lib/rustbgpd

EXPOSE 179 9179

# Default: run daemon with config at /etc/rustbgpd/config.toml
# Interop tests override with: docker run ... sleep infinity
CMD ["rustbgpd", "/etc/rustbgpd/config.toml"]
