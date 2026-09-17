//! Real-daemon regression for `rs-config-render activate` when the daemon
//! rejects the SIGHUP reload before any runtime effect.
//!
//! A member join (a generation-class change) combined with a
//! `[global] honor_graceful_shutdown` edit passes the offline strict check but
//! is rejected by the SIGHUP route classifier before any effect. The daemon
//! records exactly one `rejected_no_effect` reload outcome, keeps serving the
//! previous generation, and has no reload in flight, so `activate` must
//! re-point `current` at the previous generation and exit as rolled back
//! rather than demanding manual recovery.

#[path = "support/mod.rs"]
mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

use rs_config_render::activation::{self, Options, Status};
use rs_config_render::ixp_manager;
use rs_config_render::ixp_manager_host::{Binding, RenderBinding};
use serde_json::json;

const ROUTER_HANDLE: &str = "rs1-lan1-ipv4";

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set permissions");
}

fn client(id: u64, address: &str, prefix: &str) -> serde_json::Value {
    let asn = 65000 + id;
    json!({
        "customer_id": id,
        "vlan_interface_id": id,
        "name": format!("Member{id}"),
        "asn": asn,
        "address": address,
        "peering_ips": [address],
        "max_prefix": 100,
        "auth": {"type": "none"},
        "irr_filter": true,
        "more_specifics": false,
        "origins": [asn],
        "prefixes": [prefix]
    })
}

fn write_candidate(
    dir: &Path,
    clients: &[serde_json::Value],
    checker: &Path,
    binding: &RenderBinding,
) {
    if dir.exists() {
        fs::remove_dir_all(dir).expect("clean candidate dir");
    }
    fs::create_dir_all(dir).expect("create candidate dir");
    set_mode(dir, 0o700);
    let doc = json!({
        "schema": "rustbgpd.ixp-manager.router-config/v2",
        "ixp_manager": {"version": "7.4.0"},
        "router": {
            "handle": ROUTER_HANDLE, "type": "route-server", "protocol": 4,
            "asn": 65501, "router_id": "192.0.2.1", "peering_ip": "127.0.0.1",
            "vlan_id": 1, "quarantine": false,
            "bgp_lc": true, "rfc1997_passthru": false, "rpki": false, "skip_md5": true
        },
        "policy": {
            "minimum_prefix_length": 24,
            "rtr_caches": [],
            "no_transit": {"source": "IXP_NO_TRANSIT_ASNS_OVERRIDE", "asns": []}
        },
        "clients": clients,
        "ui_filters": [],
        "unsupported": {"active_ui_filters": [], "route_server_skin_files": []},
        "complete": {
            "handle": ROUTER_HANDLE,
            "client_count": clients.len(),
            "ui_filter_count": 0,
            "marker": format!("END_OF_RUSTBGPD_IXP_MANAGER_CONFIG_{ROUTER_HANDLE}")
        }
    });
    let bytes = serde_json::to_vec_pretty(&doc).expect("serialize fixture");
    ixp_manager::write_checked_candidate_bytes(&bytes, dir, 300, checker, binding)
        .expect("write checked candidate");
    // The export names no listen port; the daemon picks its own.
    support::edit_rendered_config(dir, checker, support::daemon_chooses_bgp_port);
}

/// Add `[global] honor_graceful_shutdown = true` to the rendered candidate.
fn enable_honor_graceful_shutdown(dir: &Path, checker: &Path) {
    support::edit_rendered_config(dir, checker, |rendered| {
        let marker = "ebgp_requires_policy = true\n";
        assert!(rendered.contains(marker), "rendered [global] marker");
        rendered.replacen(
            marker,
            &format!("{marker}honor_graceful_shutdown = true\n"),
            1,
        )
    });
}

fn rbgp(addr: &str, args: &[&str]) -> Output {
    Command::new(support::rbgp_binary())
        .arg("--addr")
        .arg(addr)
        .args(args)
        .output()
        .expect("execute rbgp")
}

struct DaemonKiller(std::path::PathBuf);

impl Drop for DaemonKiller {
    fn drop(&mut self) {
        if let Ok(text) = fs::read_to_string(&self.0)
            && let Ok(pid) = text.trim().parse::<i32>()
        {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
}

#[test]
fn real_daemon_rejected_reload_rolls_activate_back() {
    let evidence = support::RetainOnPanic::new(
        tempfile::Builder::new()
            .prefix("rs-rejected-")
            .tempdir()
            .expect("temporary evidence directory"),
    );
    let root = evidence.path();
    set_mode(root, 0o700);
    let runtime = root.join(ROUTER_HANDLE);
    let state = runtime.join("activation");
    let host = root.join("host-state");
    let candidate = root.join("candidate");
    let pid_file = root.join("rustbgpd.pid");
    let daemon_log = root.join("daemon.log");
    for dir in [&runtime, &state, &host] {
        fs::create_dir(dir).expect("create state dir");
        set_mode(dir, 0o700);
    }
    let _daemon = DaemonKiller(pid_file.clone());

    let daemon_bin = Path::new(env!("CARGO_BIN_EXE_rustbgpd"));
    let rbgp_addr = format!("unix://{}/grpc.sock", runtime.display());
    let binding = Binding::new(ROUTER_HANDLE, &runtime, &state, &host, &rbgp_addr)
        .expect("construct valid host binding");
    let render_binding = binding.render_binding();

    let activate_sh = root.join("activate.sh");
    fs::write(
        &activate_sh,
        format!(
            r#"#!/bin/sh
set -eu
if [ -f "{pid}" ] && kill -0 "$(cat "{pid}")" 2>/dev/null; then
    kill -HUP "$(cat "{pid}")"
else
    "{daemon}" "{state}/current/config.toml" >> "{log}" 2>&1 &
    echo $! > "{pid}"
fi
"#,
            pid = pid_file.display(),
            daemon = daemon_bin.display(),
            state = state.display(),
            log = daemon_log.display(),
        ),
    )
    .expect("write activate.sh");
    set_mode(&activate_sh, 0o700);
    let run = |initial: bool, settle: u64| {
        activation::activate(&Options {
            candidate: &candidate,
            state_dir: &state,
            checker: daemon_bin,
            rbgp: support::rbgp_binary(),
            rbgp_addr: &rbgp_addr,
            settle: Duration::from_secs(settle),
            initial,
            activation_command: &activate_sh,
            activation_args: &[],
            binding: &binding,
        })
    };
    let receipt = || -> serde_json::Value {
        serde_json::from_slice(&fs::read(state.join("activation-receipt.json")).unwrap()).unwrap()
    };
    let current = || fs::read_link(state.join("current")).unwrap();

    let member1 = client(1, "127.0.0.2", "198.51.100.0/24");
    write_candidate(
        &candidate,
        std::slice::from_ref(&member1),
        daemon_bin,
        &render_binding,
    );
    assert_eq!(run(true, 10), Ok(Status::Activated));
    let prior = current();

    // A member join (generation route) plus an honor-knob edit: the strict
    // check accepts the file, the SIGHUP classifier rejects it before any effect.
    write_candidate(
        &candidate,
        &[member1, client(2, "127.0.0.3", "198.51.101.0/24")],
        daemon_bin,
        &render_binding,
    );
    enable_honor_graceful_shutdown(&candidate, daemon_bin);
    let result = run(false, 3);
    let log = fs::read_to_string(&daemon_log).unwrap_or_default();
    assert_eq!(
        result,
        Err(activation::Error::RolledBack),
        "receipt:\n{:#}\ndaemon log:\n{log}",
        receipt()
    );
    assert!(
        log.contains("SIGHUP reload rejected without runtime effect"),
        "daemon must log the clean rejection:\n{log}"
    );

    let receipt = receipt();
    assert_eq!(receipt["status"], "rolled_back", "{receipt:#}");
    assert_eq!(receipt["activation_runs"], 1, "{receipt:#}");
    assert_eq!(receipt["phases"]["candidate_activation_ran"], true);
    assert_eq!(receipt["phases"]["rollback_link"]["durable"], true);
    assert_eq!(receipt["phases"]["rollback_activation_ran"], false);
    assert_eq!(receipt["phases"]["runtime_equal"], true);
    assert_eq!(
        receipt["previous_generation"].as_str(),
        prior.to_str(),
        "{receipt:#}"
    );
    assert_eq!(
        current(),
        prior,
        "current must name the previous generation"
    );
    assert!(
        !host.join("ixp-manager-host-fence.json").exists(),
        "a rolled-back activation leaves no recovery fence"
    );

    let diff = rbgp(
        &rbgp_addr,
        &[
            "config",
            "diff",
            state.join("current/config.toml").to_str().unwrap(),
        ],
    );
    assert_eq!(
        diff.status.code(),
        Some(0),
        "the daemon still runs the previous generation:\n{}",
        String::from_utf8_lossy(&diff.stdout)
    );
    let metrics = rbgp(&rbgp_addr, &["metrics"]);
    assert!(
        String::from_utf8_lossy(&metrics.stdout).lines().any(
            |line| line == "bgp_sighup_reload_outcomes_total{outcome=\"rejected_no_effect\"} 1"
        ),
        "exactly one rejected reload outcome"
    );
}
