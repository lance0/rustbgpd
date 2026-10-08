//! Privileged netns proof for the LACP partner read behind
//! `esi = "auto-lacp"` (RFC 7432 §5 type 1 ESI derivation).
//!
//! Re-exec pattern (mirrors `netns_link_carrier.rs`): the outer pass
//! creates a throwaway netns and re-runs this test inside it. The
//! inner pass joins two 802.3ad bonds over a veth pair — `pe-bond`
//! (the PE) and `ce-bond` (a synthetic CE with its own LACP system
//! MAC and user port key) — lets LACP negotiate, and asserts:
//!
//! - the PE reads the **CE's** system MAC and port key (the partner),
//!   never its own, and the derived ESI carries them in RFC 7432 §5
//!   type 1 layout;
//! - every absent or ambiguous source fails closed: missing link,
//!   non-bond, non-802.3ad bond, admin-down bond, and a bond whose
//!   peer speaks no LACP.
//!
//! Gates on `EVPN_LINUX_NETNS=1` and requires `CAP_NET_ADMIN` +
//! `CAP_SYS_ADMIN`, same as the sibling netns tests. Run via:
//!
//! ```bash
//! bash crates/evpn-linux/tests/docker/run-netns-tests.sh bond_lacp
//! ```

#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::{Duration, Instant};

use rustbgpd_evpn_linux::{LacpPartner, LacpPartnerError, read_bond_lacp_partner};

const CE_SYSTEM_MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const CE_USER_PORT_KEY: u16 = 7;
const PE_SYSTEM_MAC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
const PE_USER_PORT_KEY: u16 = 3;

fn netns_gate() -> bool {
    std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1")
}

fn run(args: &[&str]) {
    let out = Command::new("ip").args(args).output().expect("spawn ip");
    assert!(
        out.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

struct NetnsFixture {
    name: String,
}

impl NetnsFixture {
    fn create() -> Self {
        let name = format!("rustbgpd-test-bondlacp-{}", std::process::id());
        let _ = Command::new("ip").args(["netns", "delete", &name]).output();
        run(&["netns", "add", &name]);
        Self { name }
    }
}

impl Drop for NetnsFixture {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "delete", &self.name])
            .output();
    }
}

fn add_lacp_bond(name: &str, system_mac: &str, user_port_key: u16) {
    run(&[
        "link",
        "add",
        name,
        "type",
        "bond",
        "mode",
        "802.3ad",
        "lacp_rate",
        "fast",
        "ad_actor_system",
        system_mac,
        "ad_user_port_key",
        &user_port_key.to_string(),
    ]);
}

/// Poll until `bond` reports a partner; LACP fast rate converges in
/// a few seconds.
fn wait_for_partner(bond: &str) -> LacpPartner {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match read_bond_lacp_partner(bond) {
            Ok(partner) => return partner,
            Err(e) if Instant::now() < deadline => {
                eprintln!("waiting for {bond} LACP partner: {e}");
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => panic!("{bond} never learned an LACP partner: {e}"),
        }
    }
}

#[test]
fn bond_lacp_partner_yields_ce_identity_and_fails_closed() {
    if !netns_gate() {
        eprintln!(
            "skipping: set EVPN_LINUX_NETNS=1 to run the privileged bond LACP netns test \
             (requires CAP_NET_ADMIN + CAP_SYS_ADMIN)"
        );
        return;
    }

    if std::env::var("RUSTBGPD_BONDLACP_INNER").is_err() {
        let ns = NetnsFixture::create();
        let exe = std::env::current_exe().expect("self-exe");
        let status = Command::new("ip")
            .args(["netns", "exec", &ns.name])
            .arg(&exe)
            .args([
                "--exact",
                "--nocapture",
                "bond_lacp_partner_yields_ce_identity_and_fails_closed",
            ])
            .env("RUSTBGPD_BONDLACP_INNER", "1")
            .env("EVPN_LINUX_NETNS", "1")
            .status()
            .expect("spawn inner");
        assert!(status.success(), "inner test invocation failed");
        return;
    }

    // Fail-closed sources.
    assert!(matches!(
        read_bond_lacp_partner("ghost0"),
        Err(LacpPartnerError::NotFound)
    ));
    run(&["link", "add", "plain0", "type", "dummy"]);
    run(&["link", "set", "plain0", "up"]);
    assert!(matches!(
        read_bond_lacp_partner("plain0"),
        Err(LacpPartnerError::NotBond)
    ));
    run(&[
        "link",
        "add",
        "ab-bond",
        "type",
        "bond",
        "mode",
        "active-backup",
    ]);
    run(&["link", "set", "ab-bond", "up"]);
    assert!(matches!(
        read_bond_lacp_partner("ab-bond"),
        Err(LacpPartnerError::NotLacpMode)
    ));

    // PE <-> synthetic CE over a veth pair.
    add_lacp_bond("pe-bond", "02:aa:bb:cc:dd:ee", PE_USER_PORT_KEY);
    add_lacp_bond("ce-bond", "02:11:22:33:44:55", CE_USER_PORT_KEY);
    run(&[
        "link", "add", "pe-port", "type", "veth", "peer", "name", "ce-port",
    ]);
    run(&["link", "set", "pe-port", "master", "pe-bond"]);
    run(&["link", "set", "ce-port", "master", "ce-bond"]);
    assert!(
        matches!(
            read_bond_lacp_partner("pe-bond"),
            Err(LacpPartnerError::Down)
        ),
        "an admin-down bond must not yield a partner"
    );
    run(&["link", "set", "ce-bond", "up"]);
    run(&["link", "set", "pe-bond", "up"]);

    let partner = wait_for_partner("pe-bond");
    assert_eq!(
        partner.system_mac, CE_SYSTEM_MAC,
        "the PE must read the CE's LACP system MAC, not its own"
    );
    // The operational key's top ten bits are the configured user port
    // key; the low bits encode speed and duplex.
    assert_eq!(
        partner.port_key >> 6,
        CE_USER_PORT_KEY,
        "the PE must read the CE's port key (got {:#06x})",
        partner.port_key
    );
    let [key_hi, key_lo] = partner.port_key.to_be_bytes();
    assert_eq!(
        rustbgpd_evpn::lacp_type1_esi(partner.system_mac, partner.port_key).octets(),
        [
            0x01, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, key_hi, key_lo, 0x00
        ]
    );

    // Symmetry: the CE sees the PE as its partner.
    let reverse = wait_for_partner("ce-bond");
    assert_eq!(reverse.system_mac, PE_SYSTEM_MAC);
    assert_eq!(reverse.port_key >> 6, PE_USER_PORT_KEY);

    // A bond whose peer speaks no LACP never yields a partner.
    add_lacp_bond("lone-bond", "02:00:00:00:00:01", 9);
    run(&[
        "link",
        "add",
        "lone-port",
        "type",
        "veth",
        "peer",
        "name",
        "lone-peer",
    ]);
    run(&["link", "set", "lone-port", "master", "lone-bond"]);
    run(&["link", "set", "lone-peer", "up"]);
    run(&["link", "set", "lone-bond", "up"]);
    // Long enough for several fast-rate LACPDU periods to pass unanswered.
    std::thread::sleep(Duration::from_secs(4));
    let lone = read_bond_lacp_partner("lone-bond");
    assert!(
        matches!(lone, Err(LacpPartnerError::NoPartner)),
        "a partnerless bond must fail closed, got {lone:?}"
    );
}
