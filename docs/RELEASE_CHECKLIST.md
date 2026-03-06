# Release Checklist

Pre-publish smoke matrix for every tagged release. All items must pass before
pushing a version tag.

---

## Automated (CI)

These run on every push and PR:

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo doc --workspace --no-deps` with `RUSTDOCFLAGS="-D warnings"`

## Manual smoke tests

Run these from a clean build (`cargo build --workspace --release`) before
tagging. The `--workspace` flag is required to build both `rustbgpd` and
`rustbgpctl`.

### CLI smoke

```bash
# Build both binaries
cargo build --workspace --release

# Start daemon with minimal config
./target/release/rustbgpd examples/minimal/config.toml &
DAEMON_PID=$!
sleep 2

# Verify CLI commands parse and connect
export RUSTBGPD_ADDR=unix:///tmp/rustbgpd/grpc.sock
./target/release/rustbgpctl health
./target/release/rustbgpctl global
./target/release/rustbgpctl neighbor
./target/release/rustbgpctl rib
./target/release/rustbgpctl metrics

kill $DAEMON_PID
```

### UDS default smoke

Verify the daemon creates the gRPC socket at the configured
`runtime_state_dir`:

```bash
ls -la /tmp/rustbgpd/grpc.sock   # should exist after daemon start
```

### Token auth smoke

```bash
echo "test-token-value" > /tmp/rustbgpd-token
cat > /tmp/rustbgpd-auth-test.toml <<'EOF'
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 1179
runtime_state_dir = "/tmp/rustbgpd-auth"

[global.telemetry]
prometheus_addr = "127.0.0.1:19179"
log_format = "json"

[global.telemetry.grpc_uds]
path = "/tmp/rustbgpd-auth/grpc.sock"
token_file = "/tmp/rustbgpd-token"
EOF

./target/release/rustbgpd /tmp/rustbgpd-auth-test.toml &
DAEMON_PID=$!
sleep 2

# Without token — should fail
./target/release/rustbgpctl -s unix:///tmp/rustbgpd-auth/grpc.sock health 2>&1 | grep -i "error\|unauthenticated"

# With token — should succeed
./target/release/rustbgpctl -s unix:///tmp/rustbgpd-auth/grpc.sock --token-file /tmp/rustbgpd-token health

kill $DAEMON_PID
rm -rf /tmp/rustbgpd-auth /tmp/rustbgpd-token /tmp/rustbgpd-auth-test.toml
```

### Interop smoke (requires Docker + containerlab)

Run at least one from each category:

```bash
docker build -t rustbgpd:dev .

# Basic eBGP + RIB
containerlab deploy -t tests/interop/m4-frr.clab.yml
bash tests/interop/scripts/test-m4-frr.sh
containerlab destroy -t tests/interop/m4-frr.clab.yml

# Route server + policy
containerlab deploy -t tests/interop/m13-policy-frr.clab.yml
bash tests/interop/scripts/test-m13-policy-frr.sh
containerlab destroy -t tests/interop/m13-policy-frr.clab.yml

# Graceful Restart
containerlab deploy -t tests/interop/m11-gr-frr.clab.yml
bash tests/interop/scripts/test-m11-gr-frr.sh
containerlab destroy -t tests/interop/m11-gr-frr.clab.yml
```

### Docker smoke

```bash
docker build -t rustbgpd:dev .

# Verify both binaries are present
docker run --rm --entrypoint sh rustbgpd:dev -c \
  "ls /usr/local/bin/rustbgpd /usr/local/bin/rustbgpctl"

# Verify rustbgpctl parses subcommands
docker run --rm --entrypoint rustbgpctl rustbgpd:dev --help
```

## Release steps

1. Update `CHANGELOG.md` with the new version section
2. Bump version in root `Cargo.toml` (workspace version + internal deps)
3. Run the full checklist above
4. Commit: `Bump version to vX.Y.Z`
5. Tag: `git tag vX.Y.Z`
6. Push: `git push origin main && git push origin vX.Y.Z`
7. Verify CI passes on the tag
8. Verify container image published to GHCR (tagged builds)
