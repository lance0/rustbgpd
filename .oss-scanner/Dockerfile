# OSS Scanner image for rustbgpd: the daemon, the rbgp CLI and the workspace crates they are built from.
#
# The scanner builds this file with the repository checkout as the build context, then audits the image with no
# network access. This build therefore fetches every crate in Cargo.lock and the dependencies of every cargo-fuzz
# crate, and only then builds. It compiles the default workspace members in the dev profile (debug assertions and
# overflow checks on): the rustbgpd and rbgp binaries, the examples and every test binary. It also builds the wire
# fuzz targets and runs the test suite; a failing or timed-out test fails the build. threat_model.md, next to this
# file, explains how to run all of it.

# Latest stable Rust; the workspace needs at least the rust-version in Cargo.toml.
FROM rust:1-trixie
ENV DEBIAN_FRONTEND=noninteractive
# protoc compiles the gRPC API definitions in proto/. jq is used by the lab and bench scripts that some tests drive.
# iproute2 lets tests and reproducers inspect sockets.
RUN apt-get update && apt-get install -y --no-install-recommends \
      protobuf-compiler jq iproute2 python3 \
    && rm -rf /var/lib/apt/lists/*

# Build and test as an unprivileged user. Several tests inject filesystem permission failures, which root bypasses,
# and some refuse to run as root. The toolchain directories are handed to that user so cargo and rustup can write
# their caches.
RUN useradd --create-home --uid 1000 builder \
    && chown -R builder:builder /usr/local/cargo /usr/local/rustup

# scanner contract: the checkout lives inside the image, at /src
COPY --chown=builder:builder . /src
WORKDIR /src
USER builder

# A full debug build of every test binary is about 70 GB, most of it incremental caches and full debug info linked
# into each of ~140 test binaries. Line tables keep file:line backtraces and keep the image near 20 GB.
ENV RUST_BACKTRACE=1 \
    CARGO_TERM_COLOR=never \
    CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_DEV_DEBUG=line-tables-only
ARG CARGO_BUILD_JOBS=16
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

# Every crate in Cargo.lock, for every target and feature.
RUN cargo fetch --locked

# The fuzz targets live in per-crate cargo-fuzz workspaces (crates/*/fuzz) built with the nightly pinned in
# fuzz/rust-nightly.txt and the cargo-fuzz version CI uses. Fetch each one's dependencies so they build offline.
RUN rustup toolchain install "$(cat fuzz/rust-nightly.txt)" --profile minimal \
    && cargo "+$(cat fuzz/rust-nightly.txt)" install cargo-fuzz --version 0.13.2 --locked \
    && for dir in crates/*/fuzz; do (cd "$dir" && cargo "+$(cat /src/fuzz/rust-nightly.txt)" fetch) || exit 1; done

# Everything is fetched. From here on cargo must not try to reach a registry.
ENV CARGO_NET_OFFLINE=true

# The default workspace members (everything except the bench/scale measurement harnesses): libraries, the rustbgpd and
# rbgp binaries, examples and every test binary. A step that fails fails the build, and primary_contact gets the log.
RUN cargo build --locked --bins --examples \
    && cargo test --locked --no-run

# The wire-decoder fuzz targets (the main network attack surface), built with AddressSanitizer as cargo-fuzz does.
RUN cd crates/wire && RUSTUP_TOOLCHAIN="$(cat /src/fuzz/rust-nightly.txt)" cargo fuzz build

# The suite takes about ten minutes on 8 CPUs. The bound leaves room inside the scanner's build limit, and a test
# failure or a timeout fails the build.
RUN timeout 1200 cargo test --locked --no-fail-fast

# The scanner's audit shell runs as root.
USER root
