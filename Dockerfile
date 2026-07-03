# syntax=docker/dockerfile:1.7

# rustbgpd container image.
#
# Two consumable stages:
#
#   runtime (DEFAULT) — lean production image: the daemon + the `rbgp`
#     CLI, nonroot user, nothing else. This is what the GHCR release
#     image publishes (.github/workflows/container.yml builds the
#     default target).
#   dev — interop / CI / lab image: adds the EVPN load-gen helpers
#     (evpn-tester / evpn-monitor), the interop start script, and
#     iproute2/ping for containerlab topologies.
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
#   docker build -t rustbgpd:latest .                    # lean runtime
#   docker build --target dev -t rustbgpd:dev .          # dev / interop
#
# BuildKit is required for the `RUN --mount=type=cache` directives
# below; the legacy Docker builder rejects them with a parse error.
# Modern Docker (>= 23.0) and buildx enable BuildKit by default, and
# the CI workflows use `docker/build-push-action@v7` which is
# BuildKit-native — see .github/workflows/interop.yml and
# kernel-dataplane.yml. If you hit a parse error on the cache mounts,
# either upgrade Docker or set `DOCKER_BUILDKIT=1` explicitly.

FROM rust:1.95-bookworm AS chef
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
    cp target/ci/rbgp /out/ && \
    cp target/ci/evpn-tester /out/ && \
    cp target/ci/evpn-monitor /out/

# ── dev: interop / CI / lab image ────────────────────────────────────
# Ships the daemon + CLI plus the development-only helpers the
# containerlab topologies and soak harnesses expect. Runs as root so
# labs can program links/netns freely.
FROM debian:bookworm-slim AS dev

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/rustbgpd /usr/local/bin/rustbgpd
COPY --from=builder /out/rbgp /usr/local/bin/rbgp
COPY --from=builder /out/evpn-tester /usr/local/bin/evpn-tester
COPY --from=builder /out/evpn-monitor /usr/local/bin/evpn-monitor
COPY tests/interop/scripts/start-rustbgpd.sh /usr/local/bin/start-rustbgpd.sh

RUN mkdir -p /var/lib/rustbgpd

EXPOSE 179 9179

# Default: run daemon with config at /etc/rustbgpd/config.toml
# Interop tests override with: docker run ... sleep infinity
CMD ["rustbgpd", "/etc/rustbgpd/config.toml"]

# ── runtime: lean production image (DEFAULT target) ──────────────────
# Daemon + rbgp only — no dev/test/bench helpers. Runs as a nonroot
# user; Docker's default net.ipv4.ip_unprivileged_port_start=0 lets it
# bind port 179 (grant CAP_NET_BIND_SERVICE explicitly on runtimes
# that don't, e.g. some Kubernetes setups). Kernel-dataplane features
# (Linux FIB / EVPN VTEP) additionally need CAP_NET_ADMIN — see
# docs/deployment.md.
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --user-group --home-dir /var/lib/rustbgpd \
       --shell /usr/sbin/nologin rustbgpd \
    && mkdir -p /var/lib/rustbgpd \
    && chown rustbgpd:rustbgpd /var/lib/rustbgpd

COPY --from=builder /out/rustbgpd /usr/local/bin/rustbgpd
COPY --from=builder /out/rbgp /usr/local/bin/rbgp

USER rustbgpd

EXPOSE 179 9179

CMD ["rustbgpd", "/etc/rustbgpd/config.toml"]
