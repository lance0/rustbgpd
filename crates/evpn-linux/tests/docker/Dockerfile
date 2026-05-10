# Privileged-test harness for the Gate 8b BUM-suppression spike +
# Linux netlink round-trip. Provides a kernel-aware Linux userland
# (iproute2, iputils-ping with broadcast) plus the Rust toolchain so
# the gated `EVPN_LINUX_NETNS=1` tests can run inside a single
# `docker run --cap-add=NET_ADMIN ... cargo test` invocation.
#
# Build:
#   docker build -f crates/evpn-linux/tests/docker/Dockerfile \
#     -t rustbgpd-netns-tests .
#
# Run (preferred — uses the helper at the same path):
#   bash crates/evpn-linux/tests/docker/run-netns-tests.sh
#
# Run (manual):
#   docker run --rm \
#     --cap-add=NET_ADMIN \
#     --cap-add=SYS_ADMIN \
#     --security-opt apparmor=unconfined \
#     -e EVPN_LINUX_NETNS=1 \
#     -v "$(pwd)":/work -w /work \
#     -v cargo-cache:/usr/local/cargo/registry \
#     -v target-cache:/work/target \
#     rustbgpd-netns-tests \
#     cargo test -p rustbgpd-evpn-linux --test netns_bum_filter \
#       -- --test-threads=1 --nocapture
#
# Why both NET_ADMIN and SYS_ADMIN: `ip netns add` needs SYS_ADMIN
# (it calls unshare(CLONE_NEWNET)); `bridge link set` needs NET_ADMIN.
# `--cap-add` keeps the surface tighter than `--privileged`.

FROM rust:1.92-bookworm

# Toolchain bits that the privileged tests shell out to:
#   - iproute2: `ip netns`, `ip link`, `bridge link`, `bridge fdb`
#   - iputils-ping: broadcast pings (`ping -b`)
#   - procps: `sysctl` (used by the spike to enable broadcast pings)
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Same protobuf-compiler the workspace's main Dockerfile installs, so
# tonic-build doesn't try to fetch one at test-compile time.
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# No COPY — the runner bind-mounts the repo at /work so test runs
# don't need a rebuild on every code change. Cargo's incremental
# compile + the volume-mounted target/ + registry caches give a
# warm-start of seconds instead of minutes.

CMD ["bash"]
