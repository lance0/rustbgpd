# syntax=docker/dockerfile:1.7

# rustbgpd container image.
#
# Two consumable stages:
#
#   runtime (DEFAULT) — lean production image: the daemon, the `rbgp`
#     CLI, and the Birdwatcher adapter, nonroot user, nothing else. This is what the GHCR release
#     image publishes (.github/workflows/container.yml builds the
#     default target). Built with the full `release` profile (fat-LTO,
#     codegen-units=1) and `--features jemalloc` — the exact build
#     every number in docs/benchmarks.md is measured on.
#   dev — interop / CI / lab image: adds the EVPN load-gen helpers
#     (evpn-tester / evpn-monitor), the interop start script, and
#     iproute2/ping for containerlab topologies. Built with the fast
#     `ci` profile — interop M-jobs rebuild this image constantly and
#     the fat-LTO serial link would slow every lab run.
#
# Multi-stage build with cargo-chef separating dep compilation from
# workspace compilation. Two builder stages share the planner recipe
# and the BuildKit cache mounts; only the stages a given --target
# needs are built.
#
# Cache levers:
#   - cargo-chef: dep build layer invalidates only on Cargo.lock change
#   - BuildKit cache mounts: the registry persists across builds, and so
#     does the release target; the dev image keeps its cooked target in
#     the dep layer so the remote CI layer cache can carry it
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
RUN cargo chef prepare --recipe-path recipe.json && \
    scripts/source-id.sh > source-id

# ── builder: fast `ci`-profile build for the dev image ───────────────
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
# Cook deps. This layer invalidates only when Cargo.lock or a manifest
# changes, so everyday source-only commits skip it. The cooked target/
# lives in the layer itself, not in a cache mount: a cache mount is local
# to one BuildKit host and is never exported, so a CI runner restoring
# this layer from the remote cache would otherwise find no dependency
# artifacts and compile every dependency again in the workspace build.
# `--workspace` matches that build, which also covers members outside
# default-members (the bench/scale harnesses).
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo chef cook --profile ci --workspace --recipe-path recipe.json
COPY . .
# Build the workspace on the cooked layer and stash binaries in /out for
# the final stage, then drop target/ so this layer holds only /out.
#
# Cargo decides freshness by mtime, and COPY keeps the context's mtimes,
# so sources older than the cooked placeholder artifacts would look up
# to date. Touching the copied sources first makes Cargo rebuild every
# workspace crate from them; dependency artifacts stay cooked.
# `touch -h` updates a symlink itself, so a dangling one cannot fail the
# step.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    find . -path ./target -prune -o -exec touch -h {} + && \
    cargo build --workspace --profile ci && \
    mkdir -p /out && \
    cp target/ci/rustbgpd /out/ && \
    cp target/ci/rbgp /out/ && \
    cp target/ci/evpn-tester /out/ && \
    cp target/ci/evpn-monitor /out/ && \
    cp target/ci/rustbgpd-gobgp-bridge /out/ && \
    rm -rf target

# ── builder-release: benchmarked-profile build for the runtime image ─
# Full `release` profile (fat-LTO, codegen-units=1) with jemalloc as
# the global allocator — the published image must be the same build
# the benchmarks are measured on, not the CI-shaped one.
FROM chef AS builder-release
COPY --from=planner /build/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo chef cook --release --features rustbgpd/jemalloc --recipe-path recipe.json
COPY . .
# Same shared-cache mtime guard as the builder stage.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    find . -path ./target -prune -o -exec touch -h {} + && \
    cargo build --release --features rustbgpd/jemalloc \
      -p rustbgpd -p rustbgpctl -p birdwatcher-adapter && \
    mkdir -p /out && \
    cp target/release/rustbgpd /out/ && \
    cp target/release/rbgp /out/ && \
    cp target/release/birdwatcher-adapter /out/ && \
    # Bash completions for the runtime image, generated by the shipped
    # binary itself so they never drift from the build.
    /out/rbgp completions bash > /out/rbgp.bash-completion

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
COPY --from=builder /out/rustbgpd-gobgp-bridge /usr/local/bin/rustbgpd-gobgp-bridge
COPY tests/interop/scripts/start-rustbgpd.sh /usr/local/bin/start-rustbgpd.sh
# Content hash of the build inputs; compare with scripts/source-id.sh.
COPY --from=planner /build/source-id /usr/local/share/rustbgpd/source-id

RUN mkdir -p /var/lib/rustbgpd

EXPOSE 179 9179

# Default: run daemon with config at /etc/rustbgpd/config.toml
# Interop tests override with: docker run ... sleep infinity
CMD ["rustbgpd", "/etc/rustbgpd/config.toml"]

# ── runtime: lean production image (DEFAULT target) ──────────────────
# Daemon + rbgp + Birdwatcher adapter — no dev/test/bench helpers. Binaries come from
# builder-release (fat-LTO + jemalloc, the benchmarked build). Runs as
# a nonroot user; Docker's default net.ipv4.ip_unprivileged_port_start=0 lets it
# bind port 179 (grant CAP_NET_BIND_SERVICE explicitly on runtimes
# that don't, e.g. some Kubernetes setups). Kernel-dataplane features
# (Linux FIB / EVPN VTEP) additionally need CAP_NET_ADMIN — see
# docs/how-to/deployment.md.
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    # uid/gid pinned, not allocated. docs/how-to/deployment.md tells
    # operators to chown host bind mounts to 999; an unpinned system
    # account shifts whenever the base image adds an earlier one, and
    # every pre-chown'd directory silently becomes EACCES.
    && groupadd --system --gid 999 rustbgpd \
    && useradd --system --uid 999 --gid 999 --home-dir /var/lib/rustbgpd \
       --shell /usr/sbin/nologin rustbgpd \
    && mkdir -p /var/lib/rustbgpd \
    && chown rustbgpd:rustbgpd /var/lib/rustbgpd

COPY --from=builder-release /out/rustbgpd /usr/local/bin/rustbgpd
COPY --from=builder-release /out/rbgp /usr/local/bin/rbgp
COPY --from=builder-release /out/birdwatcher-adapter /usr/local/bin/birdwatcher-adapter
# Conventional bash-completion drop-in path: picked up automatically
# when the bash-completion package is present (e.g. docker exec with an
# interactive shell on a derived image).
COPY --from=builder-release /out/rbgp.bash-completion /usr/share/bash-completion/completions/rbgp
COPY LICENSE-MIT LICENSE-APACHE /
COPY --from=planner /build/source-id /usr/local/share/rustbgpd/source-id

# Numeric, not the account name: Kubernetes `runAsNonRoot: true` cannot
# resolve a name-form USER and fails the container at admission unless
# the pod spec repeats `runAsUser`.
USER 999:999

EXPOSE 179 9179

# Authenticated gRPC responsiveness only; core actor readiness is available
# through an explicit `rbgp health` override. The default endpoint is the
# local socket; set RUSTBGPD_ADDR if configuration moves it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD rbgp health --liveness

CMD ["rustbgpd", "/etc/rustbgpd/config.toml"]
