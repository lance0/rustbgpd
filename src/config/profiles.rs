//! Starter config profiles for `rustbgpd --init-config <profile>`.
//!
//! Each profile is a **hand-curated, commented** TOML string — not a
//! serialized `Config` value. Serializing the real struct would emit a
//! wall of defaulted fields and empty sections despite a few deliberately
//! sparse default-empty policy fields, and generic post-filtering risks
//! silently dropping real fields later, so a curated template gives full
//! control over layout and comments. The `every_profile_validates` test
//! round-trips each template through
//! `Config::load_toml_with_diagnostics`, so a profile that drifts out of
//! sync with the schema fails CI rather than shipping a broken bootstrap
//! — that test is the contract that makes the curated approach safe.

/// Profile names accepted by `--init-config`. Kept in sync with
/// [`profile_toml`] by the `every_listed_profile_resolves` test.
pub const PROFILE_NAMES: &[&str] = &["lab", "edge", "route-server"];

/// Return the curated starter TOML for `name`, or `None` for an unknown
/// profile.
#[must_use]
pub fn profile_toml(name: &str) -> Option<&'static str> {
    match name {
        "lab" => Some(LAB),
        "edge" => Some(EDGE),
        "route-server" => Some(ROUTE_SERVER),
        _ => None,
    }
}

/// `lab` — a minimal single-box setup for experimenting locally: one
/// eBGP neighbor, gRPC over a local Unix socket, runtime state under
/// `/tmp`. Local gRPC access rides the owner-only socket: filesystem
/// permissions authenticate, and the socket owner is authorized as the
/// implicit `local-operator` principal, so no explicit security block
/// is needed. Its permit-all policy is written out and labeled rather
/// than left to omission, so `--check --strict` is clean and the
/// posture is a choice.
const LAB: &str = r#"# rustbgpd "lab" profile — a minimal local setup for experimenting on
# one machine. Edit the ASNs and addresses for your topology, then:
#   rustbgpd config-lab.toml          # (after saving this output)
#   rbgp -s unix:///tmp/rustbgpd/grpc.sock neighbor

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
# Runtime state (gRPC socket, GR markers, event DB) lives here. /tmp is
# fine for a throwaway lab; use a persistent path in any real deployment.
runtime_state_dir = "/tmp/rustbgpd"
# RFC 8212: an eBGP neighbor with no explicit policy carries nothing in
# that direction. The chains below are what make this session pass
# traffic, so deleting one stops the session instead of quietly falling
# back to permit-all. Startup-only — SIGHUP keeps the running value, so
# changing it takes a daemon restart.
ebgp_requires_policy = true

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

# Local control socket for rbgp. The socket is owner-only (mode 0600), so
# filesystem permissions authenticate access and the socket owner is
# authorized as the implicit "local-operator" principal at operator tier —
# no [security.grpc] block needed for local operation. To add remote or
# named access (more principals, TCP, mTLS), see docs/reference/configuration.md
# under [security.grpc].
[global.telemetry.grpc_uds]
enabled = true
path = "/tmp/rustbgpd/grpc.sock"
mode = 0o600

# ==========================================================================
# DELIBERATE LAB POSTURE: PERMIT ALL, BOTH DIRECTIONS. NOT FOR PRODUCTION.
# ==========================================================================
# These two chains accept every route the peer sends and re-advertise every
# route selected for it, unchanged. That is the point of a lab — see traffic,
# filter nothing — and it is exactly what must not reach a production edge.
# Replace both with real prefix / AS_PATH / community rules before this
# config peers with anything you do not own.
#
# They are spelled out rather than omitted on purpose: omitting them is the
# same permit-all, and nothing downstream can then tell an operator who meant
# it from one who forgot. Written out, `rustbgpd --check --strict` is clean
# and this comment is the record of the choice.
[policy.definitions.lab-permit-all-import]
default_action = "permit"

[policy.definitions.lab-permit-all-export]
default_action = "permit"

# Apply the named chains globally (every neighbor without an override).
[policy]
import_chain = ["lab-permit-all-import"]
export_chain = ["lab-permit-all-export"]

# Import-decision explain, on. `rbgp policy explain --neighbor 10.0.0.2
# --prefix <cidr>` then says what import policy did to a route, including
# routes it denied — which is most of what a lab is for. Explain is
# opt-in daemon-wide because the cache is per session and its cost
# multiplies by peer count; one peer is a few MiB. Spelled out so the
# posture is visible here rather than inherited.
[policy.explain]
enabled = true

# One eBGP neighbor to bring a session up against.
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "lab-peer"
hold_time = 90
"#;

/// `edge` — an eBGP edge skeleton: one upstream neighbor with a named
/// import-policy chain that drops the default route and a default-deny
/// export chain the operator fills in. Fill in your ASN, neighbor, and
/// prefix filters.
const EDGE: &str = r#"# rustbgpd "edge" profile — an eBGP edge skeleton: one upstream
# transit/peer neighbor with a named import-policy chain and a
# default-deny export chain to fill in. Replace the ASN, neighbor
# address, and extend the filters with your own prefix / AS_PATH /
# community rules.

[global]
asn = 65100
router_id = "203.0.113.1"
listen_port = 179
runtime_state_dir = "/var/lib/rustbgpd"
# RFC 8212: an eBGP neighbor with no explicit policy carries nothing in
# that direction. Deleting either chain below therefore fails closed
# rather than quietly reverting to permit-all — on an edge that is the
# difference between an outage and a route leak. Startup-only — SIGHUP
# keeps the running value, so changing it takes a daemon restart.
ebgp_requires_policy = true

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

# Local control socket for rbgp. The socket is owner-only (mode 0600), so
# filesystem permissions authenticate access and the socket owner is
# authorized as the implicit "local-operator" principal at operator tier —
# no [security.grpc] block needed for local operation. To add remote or
# named access (more principals, TCP, mTLS), see docs/reference/configuration.md
# under [security.grpc].
[global.telemetry.grpc_uds]
enabled = true
path = "/var/lib/rustbgpd/grpc.sock"
mode = 0o600

# Named import policy: permit by default, but drop the IPv4 default
# route from upstream. Add more statements (RPKI, AS_PATH, communities)
# above the default as needed.
[policy.definitions.from-upstream]
default_action = "permit"

[[policy.definitions.from-upstream.statements]]
action = "deny"
prefix = "0.0.0.0/0"

# Named export policy: deny by default, and empty on purpose. Add one
# permit statement per prefix this AS originates, for example:
#
#   [[policy.definitions.to-upstream.statements]]
#   action = "permit"
#   prefix = "203.0.113.0/24"
#
# Bare `prefix` is an exact match; add `ge`/`le` only where you mean to
# announce more-specifics. Until a statement is added the upstream is
# advertised nothing, which is the direction a skeleton should fail in —
# an export chain filled in by guesswork is how a leak ships.
[policy.definitions.to-upstream]
default_action = "deny"

# Apply the named chains globally (every neighbor without an override).
[policy]
import_chain = ["from-upstream"]
export_chain = ["to-upstream"]

# Import-decision explain, off. An upstream transit sends a full table;
# the per-session cache defaults to 4096 entries, so an enabled cache
# stays saturated and answers most queries with an evicted result while
# still costing per session. Turn it on with `cache_size` raised toward
# the peer's retained-prefix count while you are debugging a specific
# import decision, and own the memory. Stated rather than inherited so
# the choice is visible on the page.
[policy.explain]
enabled = false

[[neighbors]]
address = "203.0.113.2"
remote_asn = 64500
description = "upstream-transit"
hold_time = 90
"#;

/// `route-server` — a self-contained IPv4 route-server skeleton with two
/// eBGP member placeholders and an explicit fail-closed import posture.
/// The export chain is deliberately transparent; operators must replace
/// every placeholder and install site-specific import hygiene before use.
const ROUTE_SERVER: &str = r#"# rustbgpd "route-server" profile — a self-contained IPv4
# two-member skeleton. Replace every ASN, address, and member limit before use.
# The installed starter deliberately has no external policy files, datasets,
# RTR source, or snapshot dependency. For the full production example and
# rendered member inventories, see:
#   https://github.com/lance0/rustbgpd/tree/main/examples/route-server
#   https://github.com/lance0/rustbgpd/tree/main/tools/rs-config-render

[global]
asn = 65500
router_id = "198.51.100.1"
listen_port = 179
runtime_state_dir = "/var/lib/rustbgpd"
# RFC 8212: explicit import and export chains are required for eBGP. Removing
# either chain below fails closed instead of silently reverting to permit-all.
# Startup-only — changing this value requires a daemon restart.
ebgp_requires_policy = true

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

# Local control socket for rbgp. The socket is owner-only (mode 0600), so
# filesystem permissions authenticate access and the socket owner is
# authorized as the implicit "local-operator" principal at operator tier.
[global.telemetry.grpc_uds]
enabled = true
path = "/var/lib/rustbgpd/grpc.sock"
mode = 0o600

# Import defaults deny. Before accepting member routes, add site policy that
# validates IRR-derived member prefixes and origins and applies the intended
# RPKI hygiene. The full example and rs-config-render links above show the
# production policy and generated member inventory paths.
[policy.definitions.rs-member-import]
default_action = "deny"

# Route-server export is explicitly transparent: selected routes pass to
# members without the starter inventing an outbound filtering policy.
[policy.definitions.rs-transparent-export]
default_action = "permit"

[policy]
import_chain = ["rs-member-import"]
export_chain = ["rs-transparent-export"]

# Import-decision explain is disabled: enable it deliberately while debugging
# and size the per-session cache for the retained member-route workload.
[policy.explain]
enabled = false

[[neighbors]]
address = "198.51.100.2"
remote_asn = 64501
description = "member-alpha"
hold_time = 90
families = ["ipv4_unicast"]
route_server_client = true
role = "route_server"
next_hop_ownership = "strict_peer"
# Replace with this member's contracted inbound IPv4 prefix limit.
max_prefixes = 50000

[[neighbors]]
address = "198.51.100.3"
remote_asn = 64502
description = "member-beta"
hold_time = 90
families = ["ipv4_unicast"]
route_server_client = true
role = "route_server"
next_hop_ownership = "strict_peer"
# Replace with this member's contracted inbound IPv4 prefix limit.
max_prefixes = 50000
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BgpRoleConfig, Config, GrpcEnforcementConfig, NextHopOwnershipConfig};

    #[test]
    fn every_profile_validates() {
        // The contract that makes hand-curated templates safe: each one
        // must round-trip through the real config validator. A schema
        // change that breaks a profile fails here, loudly.
        for name in PROFILE_NAMES {
            let toml = profile_toml(name).expect("listed profile must resolve");
            Config::load_toml_with_diagnostics(toml, name)
                .unwrap_or_else(|e| panic!("--init-config {name} must validate, got:\n{e}"));
        }
    }

    #[test]
    fn every_profile_relies_on_the_implicit_local_operator_uds() {
        // Load-bearing bootstrap contract: profiles validate clean under
        // the default tier enforcement with NO explicit security block —
        // the owner-only UDS grants the implicit `local-operator`
        // identity. Restoring legacy enforcement, widening the socket
        // mode, adding a principal back, or dropping the explanatory
        // comment makes this test fail instead of shipping ceremony (or
        // an unexplained implicit grant) to new operators.
        for name in PROFILE_NAMES {
            let toml = profile_toml(name).expect("listed profile must resolve");
            let config = Config::load_toml_with_diagnostics(toml, name)
                .unwrap_or_else(|e| panic!("--init-config {name} must validate, got:\n{e}"));

            assert_eq!(
                config.security.grpc.enforcement,
                GrpcEnforcementConfig::Tier,
                "--init-config {name} must use tier gRPC enforcement"
            );
            assert!(
                config.security.grpc.roles.is_empty(),
                "--init-config {name} must not need a [security.grpc.roles] block"
            );

            let uds = config
                .global
                .telemetry
                .grpc_uds
                .as_ref()
                .unwrap_or_else(|| panic!("--init-config {name} must declare grpc_uds"));
            assert!(
                uds.enabled,
                "--init-config {name} must enable its declared grpc_uds listener"
            );
            assert_eq!(
                uds.principal, None,
                "--init-config {name} grpc_uds must rely on the implicit identity"
            );
            assert_eq!(
                uds.mode & 0o077,
                0,
                "--init-config {name} grpc_uds must stay owner-only for the implicit grant"
            );
            assert!(
                toml.contains("local-operator"),
                "--init-config {name} must explain the implicit local-operator rule"
            );
        }
    }

    #[test]
    fn route_server_profile_pins_the_self_contained_ipv4_skeleton() {
        let toml = profile_toml("route-server").expect("route-server profile must resolve");
        let config = Config::load_toml_with_diagnostics(toml, "route-server")
            .expect("route-server profile must validate");

        assert_eq!(config.global.ebgp_requires_policy, Some(true));
        assert_eq!(config.policy.import_chain, ["rs-member-import"]);
        assert_eq!(config.policy.export_chain, ["rs-transparent-export"]);
        assert_eq!(config.policy.definitions.len(), 2);
        assert_eq!(
            config.policy.definitions["rs-member-import"].default_action,
            "deny"
        );
        assert_eq!(
            config.policy.definitions["rs-transparent-export"].default_action,
            "permit"
        );

        assert!(config.rpki.is_none());
        assert!(config.policy.rpol_files.is_empty());
        assert!(config.policy.rpol_roots.is_empty());
        assert!(config.policy.datasets.is_empty());

        assert_eq!(config.neighbors.len(), 2);
        for (neighbor, (address, remote_asn)) in config
            .neighbors
            .iter()
            .zip([("198.51.100.2", 64_501), ("198.51.100.3", 64_502)])
        {
            assert_eq!(neighbor.address, address);
            assert_eq!(neighbor.remote_asn, remote_asn);
            assert_ne!(neighbor.remote_asn, config.global.asn);
            assert_eq!(neighbor.families, ["ipv4_unicast"]);
            assert_eq!(neighbor.route_server_client, Some(true));
            assert_eq!(neighbor.role, Some(BgpRoleConfig::RouteServer));
            assert_eq!(
                neighbor.next_hop_ownership,
                Some(NextHopOwnershipConfig::StrictPeer)
            );
            assert_eq!(neighbor.max_prefixes, Some(50_000));
        }

        for pointer in ["examples/route-server", "tools/rs-config-render"] {
            assert!(
                toml.contains(pointer),
                "route-server profile must point operators to {pointer}"
            );
        }
    }

    #[test]
    fn every_listed_profile_resolves() {
        for name in PROFILE_NAMES {
            assert!(
                profile_toml(name).is_some(),
                "PROFILE_NAMES lists {name} but profile_toml has no arm"
            );
        }
    }

    #[test]
    fn unknown_profile_is_none() {
        assert!(profile_toml("nope").is_none());
        assert!(profile_toml("").is_none());
    }
}
