//! `rustbgpd --check` refuses an interface-only neighbor (ADR-0142) when the
//! process cannot open the raw ICMPv6 socket Router Advertisement discovery
//! needs, and names `CAP_NET_RAW` in the error.

#![cfg(target_os = "linux")]

use std::process::Command;

/// `CAP_NET_RAW` (bit 13) in this process's effective set: the child
/// inherits it, so the expected outcome follows from it.
fn has_cap_net_raw() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("CapEff:")
                    .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
            })
        })
        .is_some_and(|caps| caps & (1 << 13) != 0)
}

fn check(neighbor: &str) -> std::process::Output {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("rustbgpd.toml");
    std::fs::write(
        &config,
        format!(
            "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\
             runtime_state_dir = \"{}\"\n\n[global.telemetry]\nlog_format = \"json\"\n\n{neighbor}",
            temp.path().display()
        ),
    )
    .expect("write config");
    Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .arg("--check")
        .arg(&config)
        .env("NO_COLOR", "1")
        .output()
        .expect("run rustbgpd --check")
}

#[test]
fn check_requires_cap_net_raw_only_for_interface_only_neighbors() {
    let interface_only = check("[[neighbors]]\ninterface = \"swp1\"\nremote_asn = \"external\"\n");
    let stderr = String::from_utf8_lossy(&interface_only.stderr);
    if has_cap_net_raw() {
        assert!(interface_only.status.success(), "{interface_only:?}");
    } else {
        // Mutation-red: dropping the probe lets this config pass `--check`.
        assert_eq!(interface_only.status.code(), Some(1), "{interface_only:?}");
        assert!(stderr.contains("CAP_NET_RAW"), "{stderr}");
    }

    // A numbered neighbor never needs the capability.
    let numbered = check("[[neighbors]]\naddress = \"192.0.2.2\"\nremote_asn = 65002\n");
    assert!(numbered.status.success(), "{numbered:?}");
}
