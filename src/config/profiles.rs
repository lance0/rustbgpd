//! Starter config profiles for `rustbgpd --init-config <profile> --stdout`.
//!
//! Each profile is a **hand-curated, commented** TOML string — not a
//! serialized `Config` value. Serializing the real struct would emit a
//! wall of empty sections (the schema has no `skip_serializing_if`), and
//! generic post-filtering risks silently dropping real fields later, so
//! a curated template gives full control over layout and comments. The
//! `every_profile_validates` test round-trips each template through
//! `Config::load_toml_with_diagnostics`, so a profile that drifts out of
//! sync with the schema fails CI rather than shipping a broken bootstrap
//! — that test is the contract that makes the curated approach safe.

/// Profile names accepted by `--init-config`. Kept in sync with
/// [`profile_toml`] by the `every_listed_profile_resolves` test.
pub const PROFILE_NAMES: &[&str] = &["lab", "edge"];

/// Return the curated starter TOML for `name`, or `None` for an unknown
/// profile.
#[must_use]
pub fn profile_toml(name: &str) -> Option<&'static str> {
    match name {
        "lab" => Some(LAB),
        "edge" => Some(EDGE),
        _ => None,
    }
}

/// `lab` — a minimal single-box setup for experimenting locally: one
/// eBGP neighbor, gRPC over a local Unix socket, runtime state under
/// `/tmp`. No gRPC auth — fine for a throwaway lab, never production.
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

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

# Local control socket for rbgp. The lab profile ships NO gRPC
# auth — do not use this posture outside a trusted local box.
[global.telemetry.grpc_uds]
path = "/tmp/rustbgpd/grpc.sock"

[security.grpc]
# Legacy: listener-wide access, no per-principal role ceilings.
enforcement = "legacy"

# One eBGP neighbor to bring a session up against.
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "lab-peer"
hold_time = 90
"#;

/// `edge` — an eBGP edge skeleton: one upstream neighbor with a named
/// import-policy chain that drops the default route. Fill in your ASN,
/// neighbor, and prefix filters.
const EDGE: &str = r#"# rustbgpd "edge" profile — an eBGP edge skeleton: one upstream
# transit/peer neighbor with a named import-policy chain. Replace the
# ASN, neighbor address, and extend the filter with your own
# prefix / AS_PATH / community rules.

[global]
asn = 65100
router_id = "203.0.113.1"
listen_port = 179
runtime_state_dir = "/var/lib/rustbgpd"

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

# Named import policy: permit by default, but drop the IPv4 default
# route from upstream. Add more statements (RPKI, AS_PATH, communities)
# above the default as needed.
[policy.definitions.from-upstream]
default_action = "permit"

[[policy.definitions.from-upstream.statements]]
action = "deny"
prefix = "0.0.0.0/0"

# Apply the named chain globally (every neighbor without an override).
[policy]
import_chain = ["from-upstream"]

[[neighbors]]
address = "203.0.113.2"
remote_asn = 64500
description = "upstream-transit"
hold_time = 90
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

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
