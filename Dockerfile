# syntax=docker/dockerfile:1.7

# rustbgpd:dev — interop / CI / dev container.
#
# Multi-stage build with cargo-chef separating dep compilation from
# workspace compilation. Builds the `ci` profile (release-shaped but
# without fat-LTO / codegen-units=1) so the 15 workspace crates plus
# ~300 deps actually parallelize.
#
# Cache levers:
#   - cargo-chef: dep build layer invalidates only on Cargo.lock change
#   - BuildKit cache mounts: registry + target persist across builds
#   - mold linker: parallel final link, faster than the default GNU ld
#
# Build:
#   docker build -t rustbgpd:dev .
#
# BuildKit is required for the `RUN --mount=type=cache` directives
# below; the legacy Docker builder rejects them with a parse error.
# Modern Docker (>= 23.0) and buildx enable BuildKit by default, and
# the CI workflows use `docker/build-push-action@v7` which is
# BuildKit-native — see .github/workflows/interop.yml and
# kernel-dataplane.yml. If you hit a parse error on the cache mounts,
# either upgrade Docker or set `DOCKER_BUILDKIT=1` explicitly.

FROM rust:1.92-bookworm AS chef
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    mold \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install cargo-chef --version 0.1.71 --locked
WORKDIR /build
# Use mold for every cargo link in this stage and all stages that inherit.
ENV RUSTFLAGS="-C link-arg=-fuse-ld=mold"

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
# Cook deps under cache mounts. Dep layer invalidates only when
# Cargo.lock changes; everyday source-only commits skip this step.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo chef cook --profile ci --recipe-path recipe.json
COPY . .
# Build workspace + stash binaries outside the cache mount so the
# final-stage COPY can find them. The target/ cache directory is a
# tmpfs-style mount that the next stage cannot read directly.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --workspace --profile ci && \
    mkdir -p /out && \
    cp target/ci/rustbgpd /out/ && \
    cp target/ci/rustbgpctl /out/ && \
    cp target/ci/evpn-tester /out/ && \
    cp target/ci/evpn-monitor /out/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/rustbgpd /usr/local/bin/rustbgpd
COPY --from=builder /out/rustbgpctl /usr/local/bin/rustbgpctl
COPY --from=builder /out/evpn-tester /usr/local/bin/evpn-tester
COPY --from=builder /out/evpn-monitor /usr/local/bin/evpn-monitor
COPY tests/interop/scripts/start-rustbgpd.sh /usr/local/bin/start-rustbgpd.sh

RUN mkdir -p /var/lib/rustbgpd

EXPOSE 179 9179

# Default: run daemon with config at /etc/rustbgpd/config.toml
# Interop tests override with: docker run ... sleep infinity
CMD ["rustbgpd", "/etc/rustbgpd/config.toml"]
