#![no_main]

use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt as _;

use libfuzzer_sys::fuzz_target;
use rustbgpd_mrt::warm_bundle::{
    WARM_BUNDLE_MANIFEST_FILE, WARM_BUNDLE_POLICY_DIGEST_VERSION, WarmBundleDirectory,
    WarmBundleError, WarmBundleExpectedV1, WarmBundleFamilyV1, WarmBundleFreshnessV1,
    WarmBundlePolicyDigestV1, WarmBundleViewKindV1, WarmBundleViewV1, load_warm_bundle,
};

const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CREATED_AT_UTC_SECONDS: i64 = 1_800_000_000;
const CANONICAL_MANIFEST: &[u8] = include_bytes!("../seeds/warm_bundle_manifest/canonical-v1.json");

fn expected() -> WarmBundleExpectedV1 {
    WarmBundleExpectedV1 {
        checkpoint_generation: "fuzz-generation-1".to_string(),
        local_asn: 64_500,
        local_router_id: Ipv4Addr::new(10, 255, 0, 1),
        config_sha256: SHA256.to_string(),
        resolved_import_policy: WarmBundlePolicyDigestV1 {
            version: WARM_BUNDLE_POLICY_DIGEST_VERSION,
            sha256: SHA256.to_string(),
        },
        views: vec![WarmBundleViewV1 {
            kind: WarmBundleViewKindV1::AdjRibInPostImportPolicy,
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_asn: 64_501,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
            family: WarmBundleFamilyV1::Ipv4Unicast,
            add_path_receive: false,
        }],
    }
}

fn freshness() -> WarmBundleFreshnessV1 {
    WarmBundleFreshnessV1 {
        now_utc_seconds: CREATED_AT_UTC_SECONDS + 10,
        max_age_seconds: 60,
        max_future_skew_seconds: 5,
    }
}

fuzz_target!(|data: &[u8]| {
    let temp = tempfile::tempdir().expect("fuzz harness must create its private bundle directory");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .expect("fuzz harness must enforce owner-only bundle-directory permissions");
    let manifest = temp.path().join(WARM_BUNDLE_MANIFEST_FILE);
    fs::write(&manifest, data).expect("fuzz harness must write manifest input");
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600))
        .expect("fuzz harness must enforce owner-only manifest permissions");
    let directory = WarmBundleDirectory::open(temp.path())
        .expect("fuzz harness private directory must pass the production owner/mode check");

    let result = load_warm_bundle(&directory, &expected(), freshness());
    if data == CANONICAL_MANIFEST {
        assert!(
            matches!(
                &result,
                Err(WarmBundleError::Io { source, .. })
                    if source.kind() == io::ErrorKind::NotFound
            ),
            "canonical manifest must reach the absent snapshot lookup: {result:?}"
        );
    }
});
