//! DHAT ownership capture for the eager resolved-neighbor batch.
//!
//! This is separate from `policy_set_store_allocation`: DHAT owns the global
//! allocator here, while that gate uses a fixed-operation counting allocator.
//! Run the candidate and exact mechanism reversal independently:
//!
//! ```console
//! POLICY_SET_STORE_DHAT_FILE=/tmp/candidate.json cargo test -p rustbgpd \
//!   --no-default-features --features bench-internals,dhat-heap \
//!   --profile release-prof --test policy_set_store_dhat \
//!   -- --ignored --nocapture
//! ```

use std::fmt::Write as _;
use std::sync::Arc;

use rustbgpd::config::Config;

const SET_ENTRIES: usize = 10_000;
const PEERS: usize = 1_000;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

fn prefix_members() -> String {
    let mut members = String::new();
    for index in 0..SET_ENTRIES {
        if index != 0 {
            members.push_str(", ");
        }
        write!(members, "10.{}.{}.0/24", (index / 256) % 256, index % 256).unwrap();
    }
    members
}

fn fixture() -> (tempfile::TempDir, Config) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("policies")).expect("policy directory");
    let rpol = format!(
        "prefix-set shared {{ {} }}\n\
         policy shared-import {{ term allow {{ if route.prefix in shared {{ accept }} }} }}\n",
        prefix_members()
    );
    std::fs::write(dir.path().join("policies/shared.rpol"), rpol).expect("shared rpol");

    let mut config = r#"
[global]
asn = 65000
router_id = "192.0.2.254"
listen_port = 1179

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "/tmp/rustbgpd-policy-set-store.sock"
principal = "local-admin"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
local-admin = "operator"

[policy]
rpol_files = ["policies/shared.rpol"]
"#
    .to_string();
    for peer in 0..PEERS {
        writeln!(
            config,
            r#"
[[neighbors]]
address = "10.0.{}.{}"
remote_asn = {}
import_policy_chain = ["shared-import"]"#,
            peer / 250,
            peer % 250 + 1,
            64_512 + peer
        )
        .unwrap();
    }
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config).expect("config");
    let config =
        Config::load_with_diagnostics(path.to_str().unwrap()).expect("shared fixture loads");
    (dir, config)
}

/// Manual, symbolized retained-owner capture. The fixture is loaded before
/// profiling, so the profile owns only the eager `resolved_neighbors` batch.
#[test]
#[ignore = "manual eager policy-set DHAT owner receipt"]
fn shared_set_resolution_dhat() {
    let (_dir, config) = fixture();
    let output = std::env::var("POLICY_SET_STORE_DHAT_FILE")
        .expect("POLICY_SET_STORE_DHAT_FILE must name the raw JSON output");
    let profiler = dhat::Profiler::builder().file_name(output).build();

    let resolved = config
        .resolved_neighbors()
        .expect("real neighbor batch resolves");
    assert_eq!(resolved.len(), PEERS);
    let first = resolved[0].import_policy.as_ref().expect("import chain");
    let second = resolved[1].import_policy.as_ref().expect("import chain");
    let shared = Arc::ptr_eq(
        &first.policies[0].rpol.as_ref().unwrap().prefix_sets[0],
        &second.policies[0].rpol.as_ref().unwrap().prefix_sets[0],
    );
    let expect_shared = std::env::var_os("POLICY_SET_STORE_ALLOW_UNSHARED").is_none();
    if expect_shared {
        assert!(shared, "resolved neighbors must share the common set");
    }
    let canonical_copies = 1 + resolved
        .windows(2)
        .filter(|pair| {
            !Arc::ptr_eq(
                &pair[0].import_policy.as_ref().unwrap().policies[0]
                    .rpol
                    .as_ref()
                    .unwrap()
                    .prefix_sets[0],
                &pair[1].import_policy.as_ref().unwrap().policies[0]
                    .rpol
                    .as_ref()
                    .unwrap()
                    .prefix_sets[0],
            )
        })
        .count();
    assert_eq!(
        canonical_copies,
        if expect_shared { 1 } else { PEERS },
        "common-set copies must match the whole-unit sharing contract"
    );
    std::hint::black_box(&resolved);
    drop(profiler);
    std::hint::black_box(resolved);
}
