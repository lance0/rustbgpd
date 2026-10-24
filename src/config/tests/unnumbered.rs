//! ADR-0142 interface-only neighbors: the `[[neighbors]]` shape,
//! `remote_asn` modes, `[global.unnumbered]` and their validation.

use std::net::{Ipv4Addr, Ipv6Addr};

use rustbgpd_wire::notification::open_subcode;
use rustbgpd_wire::{Capability, OpenMessage};

use super::*;

const BASE: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;

fn with(extra: &str) -> String {
    format!("{BASE}{extra}")
}

const SWP1: &str = r#"
[[neighbors]]
interface = "swp1"
remote_asn = "external"
families = ["ipv6_unicast"]
"#;

fn rejected(extra: &str) -> String {
    parse(&with(extra)).unwrap_err().to_string()
}

#[test]
fn interface_only_neighbor_is_kept_apart_and_round_trips() {
    let config = parse(&with(SWP1)).unwrap();
    assert!(config.neighbors.is_empty(), "no addressed neighbor");
    let neighbor = &config.neighbors.interface_only()[0];
    assert_eq!(neighbor.interface.as_deref(), Some("swp1"));
    assert_eq!(neighbor.remote_asn, RemoteAsn::External);
    assert_eq!(neighbor.label(), "interface swp1");

    // Serialization writes it back into the one [[neighbors]] array, with
    // no address key and the string ASN form.
    let rendered = toml::to_string(&config).unwrap();
    let reparsed: Config = toml::from_str(&rendered).unwrap();
    assert_eq!(reparsed, config);
    assert!(rendered.contains("remote_asn = \"external\""), "{rendered}");
    assert!(!rendered.contains("address = \"\""), "{rendered}");
}

#[test]
fn an_absent_interface_is_accepted_at_load() {
    // Mutation-red: requiring the interface to exist (as static link-local
    // neighbors do) rejects this config.
    parse(&with(&SWP1.replace("swp1", "rbgp-absent0"))).unwrap();
}

#[test]
fn a_neighbor_without_address_or_interface_is_rejected() {
    // Mutation-red: partitioning on an empty address alone admits it as
    // interface-only.
    let error = rejected("\n[[neighbors]]\nremote_asn = 65002\n");
    assert!(error.contains("address is required"), "{error}");
}

#[test]
fn numeric_remote_asn_parses_and_resolves_exactly_as_before() {
    let config = parse(valid_toml()).unwrap();
    let neighbor = &config.neighbors[0];
    assert_eq!(neighbor.remote_asn, RemoteAsn::Asn(65002));
    let resolved = config.resolve_neighbor(neighbor).unwrap();
    assert_eq!(resolved.transport_config.peer.remote_asn, 65002);
    assert!(!resolved.transport_config.peer.remote_asn_external);
    let rendered = toml::to_string(&config).unwrap();
    assert!(rendered.contains("remote_asn = 65002"), "{rendered}");
    // The same TOML still serializes back to an identical config.
    assert_eq!(toml::from_str::<Config>(&rendered).unwrap(), config);
}

#[test]
fn remote_asn_string_forms_are_valid_on_static_neighbors() {
    for (form, asn, external) in [("\"external\"", 0, true), ("\"internal\"", 65001, false)] {
        let config =
            parse(&valid_toml().replace("remote_asn = 65002", &format!("remote_asn = {form}")))
                .unwrap();
        let resolved = config.resolve_neighbor(&config.neighbors[0]).unwrap();
        assert_eq!(resolved.transport_config.peer.remote_asn, asn, "{form}");
        assert_eq!(
            resolved.transport_config.peer.remote_asn_external, external,
            "{form}"
        );
    }
}

#[test]
fn remote_asn_zero_is_still_rejected_on_static_neighbors() {
    let error = rejected(&SWP1.replace("\"external\"", "0"));
    assert!(error.contains("must be > 0"), "{error}");
}

fn open_from(asn: u32) -> OpenMessage {
    OpenMessage {
        version: 4,
        my_as: u16::try_from(asn).unwrap(),
        hold_time: 90,
        bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: rustbgpd_wire::Afi::Ipv6,
                safi: rustbgpd_wire::Safi::Unicast,
            },
            Capability::FourOctetAs { asn },
        ],
    }
}

fn bound_peer_config(remote_asn: &str) -> rustbgpd_fsm::PeerConfig {
    let config = parse(&with(&SWP1.replace("\"external\"", remote_asn))).unwrap();
    config
        .resolve_bound_interface_neighbor(
            &config.neighbors.interface_only()[0],
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            7,
        )
        .unwrap()
        .transport_config
        .peer
}

#[test]
fn external_refuses_an_open_carrying_the_local_asn() {
    // Mutation-red: resolving "external" to the 0 accept-any wildcard
    // without the external check negotiates the iBGP OPEN.
    let peer = bound_peer_config("\"external\"");
    assert!(rustbgpd_fsm::negotiation::validate_open(&open_from(65002), &peer).is_ok());
    let error = rustbgpd_fsm::negotiation::validate_open(&open_from(65001), &peer).unwrap_err();
    assert_eq!(error.subcode, open_subcode::BAD_PEER_AS);
}

#[test]
fn internal_refuses_an_open_carrying_another_asn() {
    // Mutation-red: resolving "internal" to 0 negotiates the eBGP OPEN.
    let peer = bound_peer_config("\"internal\"");
    let mut open = open_from(65001);
    open.bgp_identifier = Ipv4Addr::new(10, 0, 0, 9);
    assert!(rustbgpd_fsm::negotiation::validate_open(&open, &peer).is_ok());
    let error = rustbgpd_fsm::negotiation::validate_open(&open_from(65002), &peer).unwrap_err();
    assert_eq!(error.subcode, open_subcode::BAD_PEER_AS);
}

#[test]
fn a_bound_neighbor_is_scoped_to_the_learned_endpoint_with_failover_forced() {
    let config = parse(&with(&format!("{SWP1}fast_external_failover = true\n"))).unwrap();
    let resolved = config
        .resolve_bound_interface_neighbor(
            &config.neighbors.interface_only()[0],
            "fe80::2".parse().unwrap(),
            7,
        )
        .unwrap();
    let transport = resolved.transport_config;
    assert_eq!(transport.remote_addr, "[fe80::2%7]:179".parse().unwrap());
    assert_eq!(transport.peer_interface.as_deref(), Some("swp1"));
    assert_eq!(transport.peer_scope_id, Some(7));
    assert!(transport.fast_external_failover);
}

#[test]
fn interface_only_rules_are_enforced() {
    let static_on_swp1 =
        "\n[[neighbors]]\naddress = \"fe80::9\"\ninterface = \"swp1\"\nremote_asn = 65009\n";
    let cases: &[(&str, &str)] = &[
        (&format!("{SWP1}{SWP1}"), "only one interface-only neighbor"),
        (
            &format!("{SWP1}{static_on_swp1}"),
            "already has a static link-local",
        ),
        (&format!("{SWP1}md5_password = \"secret\"\n"), "TCP MD5"),
        (
            &format!(
                "{SWP1}tcp_ao = {{ key = \"0123456789abcdef\", send_id = 1, recv_id = 1, algorithm = \"hmac(sha256)\" }}\n"
            ),
            "TCP-AO",
        ),
        (
            &format!("{SWP1}ttl_security = true\n"),
            "GTSM (ttl_security)",
        ),
        (
            &format!("{SWP1}fast_external_failover = false\n"),
            "fast_external_failover",
        ),
        (&SWP1.replace("swp1", " "), "must not be empty"),
    ];
    for (extra, expected) in cases {
        let error = rejected(extra);
        assert!(error.contains(expected), "{expected}: {error}");
    }
}

#[test]
fn interface_only_bfd_is_rejected_until_supported() {
    let error = rejected(&format!(
        "\n[[bfd_profiles]]\nname = \"fast\"\n{SWP1}bfd = {{ profile = \"fast\" }}\n"
    ));
    assert!(error.contains("BFD for interface-only"), "{error}");
}

#[test]
fn interface_only_neighbors_refuse_explicit_listen_addresses() {
    let config = with(SWP1).replace(
        "listen_port = 179",
        "listen_port = 179\nlisten_addresses = [\"192.0.2.1\", \"2001:db8::1\"]",
    );
    let error = parse(&config).unwrap_err().to_string();
    assert!(error.contains("listen_addresses"), "{error}");
}

#[test]
fn ra_interval_secs_is_bounded() {
    for (interval, ok) in [(3, false), (4, true), (1800, true), (1801, false)] {
        let config = with(SWP1).replace(
            "[global.telemetry]",
            &format!("[global.unnumbered]\nra_interval_secs = {interval}\n\n[global.telemetry]"),
        );
        assert_eq!(parse(&config).is_ok(), ok, "ra_interval_secs = {interval}");
    }
    let config = parse(&with(SWP1).replace(
        "[global.telemetry]",
        "[global.unnumbered]\nrouter_advertisements = false\n\n[global.telemetry]",
    ))
    .unwrap();
    assert_eq!(
        config.global.unnumbered.unwrap().router_advertisements,
        Some(false)
    );
}

#[test]
fn interface_only_edits_are_restart_required_in_the_diff() {
    let old = parse(&with(SWP1)).unwrap();
    let new = parse(&with(&SWP1.replace("\"external\"", "65002"))).unwrap();
    let diff = diff_config(&old, &new);
    assert!(diff.interface_only_neighbors_changed);
    assert!(diff.has_restart_required_changes());
    assert!(!diff_config(&old, &old).interface_only_neighbors_changed);
    // Static neighbor machinery never sees interface-only neighbors.
    let neighbor_diff = diff_neighbors(&old.neighbors, &new.neighbors);
    assert!(neighbor_diff.added.is_empty() && neighbor_diff.changed.is_empty());
}

#[test]
fn the_persisted_document_keeps_interface_only_neighbors() {
    // Mutation-red: projecting `neighbors` as the addressed slice drops the
    // interface-only neighbor from every runtime persist.
    let mut config = parse(&with(&format!(
        "{SWP1}\n[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\n"
    )))
    .unwrap();
    for document in [
        crate::config::persisted_config_document_bounded(&mut config).unwrap(),
        crate::config::raw_config_document_bounded(&mut config).unwrap(),
    ] {
        let reparsed: Config = toml::from_str(&document).unwrap();
        assert_eq!(
            reparsed.neighbors.interface_only(),
            config.neighbors.interface_only()
        );
        assert_eq!(reparsed.neighbors.len(), 1);
    }
}

#[test]
fn neighbor_record_maps_a_bound_peer_to_its_interface_only_neighbor() {
    let config = parse(&with(&format!(
        "{SWP1}export_policy_chain = []\n\n[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\n"
    )))
    .unwrap();
    let numbered = PeerKey::new("10.0.0.2".parse().unwrap(), None);
    assert_eq!(
        config.neighbor_record(&numbered).unwrap().address,
        "10.0.0.2"
    );

    let bound = PeerKey::new("fe80::2".parse().unwrap(), Some("swp1".into()));
    let record = config
        .neighbor_record(&bound)
        .expect("bound peer has a record");
    assert_eq!(record.address, "fe80::2");
    assert_eq!(record.interface.as_deref(), Some("swp1"));
    assert_eq!(record.remote_asn, RemoteAsn::External);

    // No interface-only neighbor there, or not a link-local address.
    assert!(
        config
            .neighbor_record(&PeerKey::new(
                "fe80::2".parse().unwrap(),
                Some("swp2".into())
            ))
            .is_none()
    );
    assert!(
        config
            .neighbor_record(&PeerKey::new(
                "2001:db8::2".parse().unwrap(),
                Some("swp1".into())
            ))
            .is_none()
    );
}

#[test]
fn an_unpoliced_interface_only_neighbor_is_reported() {
    // The ADR's example stanza carries no policy: --check and startup must
    // say so. Mutation-red: walking addressed neighbors only reports nothing.
    let config = parse(&with(SWP1)).unwrap();
    let unpoliced = config.unpoliced_ebgp_neighbors();
    assert_eq!(unpoliced.len(), 1);
    assert_eq!(unpoliced[0].address, "interface swp1");
    assert_eq!(unpoliced[0].remote_asn, RemoteAsn::External);
}

#[test]
fn serialization_keeps_the_operator_order_of_neighbors() {
    let numbered = |last: u8| {
        format!("\n[[neighbors]]\naddress = \"10.0.0.{last}\"\nremote_asn = 6500{last}\n")
    };
    let mut config = parse(&with(&format!("{}{SWP1}{}", numbered(2), numbered(3)))).unwrap();
    // A runtime add appends an addressed neighbor; the interface-only entry
    // stays between the two it was loaded between.
    let mut added = config.neighbors[0].clone();
    added.address = "10.0.0.4".into();
    config.neighbors.push(added);
    let rendered = toml::to_string(&config).unwrap();
    let positions: Vec<usize> = ["10.0.0.2", "swp1", "10.0.0.3", "10.0.0.4"]
        .iter()
        .map(|needle| rendered.find(needle).unwrap())
        .collect();
    // Mutation-red: chaining interface-only entries after the addressed ones
    // moves swp1 to the end.
    assert!(positions.is_sorted(), "{rendered}");
}

#[test]
fn reordering_interface_only_neighbors_is_not_a_change() {
    let swp2 = SWP1.replace("swp1", "swp2");
    let old = parse(&with(&format!("{SWP1}{swp2}"))).unwrap();
    let new = parse(&with(&format!("{swp2}{SWP1}"))).unwrap();
    // Mutation-red: an order-sensitive comparison reports a restart.
    assert!(!diff_config(&old, &new).interface_only_neighbors_changed);
    assert!(!interface_only_neighbors_changed(&old, &new));
}

#[test]
fn diff_json_keeps_remote_asn_an_integer_and_names_the_mode() {
    let old = parse(&with("")).unwrap();
    let new = parse(&with(
        "\n[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = \"external\"\n",
    ))
    .unwrap();
    let json = config_diff_json_value(&diff_config(&old, &new));
    let added = &json["reload_applied"]["neighbors"]["added"][0];
    assert_eq!(added["remote_asn"], 0);
    assert_eq!(added["remote_asn_mode"], "external");
}

#[test]
fn address_keyed_per_peer_settings_are_rejected_on_interface_only_neighbors() {
    // Mutation-red: each setting is otherwise accepted and never applied to
    // the learned peer.
    for (extra, expected) in [
        (format!("{SWP1}log_level = \"debug\"\n"), "log_level"),
        (
            format!("{SWP1}max_prefixes_out_ipv6_unicast = 10\n"),
            "outbound prefix maxima",
        ),
    ] {
        let error = rejected(&extra);
        assert!(error.contains(expected), "{expected}: {error}");
    }
    // Peer-group outbound maxima reach a bound peer through its group.
    parse(&with(&format!(
        "\n[peer_groups.fabric]\nmax_prefixes_out_ipv6_unicast = 10\n{SWP1}peer_group = \"fabric\"\n"
    )))
    .unwrap();
}

const CONDITIONAL: &str = "\n[policy.definitions.backup-routes]\ndefault_action = \"deny\"\n\n\
    [policy.definitions.transit-a]\ndefault_action = \"permit\"\n\n\
    [policy.conditional_advertisements.backup]\nadvertise_policy = \"backup-routes\"\n\
    advertise_if = \"absent\"\ncondition_prefixes = [\"0.0.0.0/0\"]\n\
    condition_policy = \"transit-a\"\n";

/// Conditional advertisements, own or inherited, are accepted on an
/// interface-only neighbor and attach at each live binding's endpoint.
#[test]
fn interface_only_conditional_advertisements_attach_at_the_binding() {
    for extra in [
        format!("{CONDITIONAL}{SWP1}conditional_advertisements = [\"backup\"]\n"),
        format!(
            "{CONDITIONAL}[peer_groups.fabric]\nconditional_advertisements = [\"backup\"]\n\
             {SWP1}peer_group = \"fabric\"\n"
        ),
    ] {
        let config = parse(&with(&extra)).unwrap();
        assert!(
            config
                .conditional_advertisement_set()
                .unwrap()
                .attachments
                .is_empty()
        );
        let learned: std::net::IpAddr = "fe80::2".parse().unwrap();
        let set = config
            .conditional_advertisement_set_with_bindings(&[(learned, "swp1".to_owned())])
            .unwrap();
        assert_eq!(
            set.attachments
                .get(&rustbgpd_rib::PeerEndpoint::new(learned, Some("swp1")))
                .map(Vec::len),
            Some(1)
        );
        assert!(
            set.definitions
                .iter()
                .any(|definition| &*definition.name == "backup")
        );
    }
}

#[test]
fn policy_validation_covers_interface_only_neighbors() {
    // A dangling named chain on an interface-only neighbor is caught like
    // any other. Mutation-red: chain checks over addressed neighbors only.
    let error = rejected(&format!("{SWP1}export_policy_chain = [\"missing\"]\n"));
    assert!(error.contains("missing"), "{error}");
}

#[test]
fn bounded_rendering_chunks_an_interface_only_neighbors_inline_policy() {
    let mut statement = parse_schema_only(&format!(
        "{}\n[policy.definitions.seed]\n[[policy.definitions.seed.statements]]\n\
         action = \"permit\"\nprefix = \"2001:db8::/32\"\nge = 48\n",
        valid_toml()
    ))
    .unwrap()
    .policy
    .definitions
    .remove("seed")
    .unwrap()
    .statements
    .remove(0);
    statement.set_med = Some(7);
    let mut config = parse(&with(&format!(
        "\n[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\n{SWP1}"
    )))
    .unwrap();
    let mut swp1 = config.neighbors.interface_only()[0].clone();
    swp1.import_policy = vec![statement; 257];
    config.neighbors.set_interface_only_for_test(vec![swp1]);

    let original = config.clone();
    let oracle = persisted_config_document(&config).unwrap();
    let (bounded, stats) = super::canonical::render_document_bounded(&mut config).unwrap();
    // Mutation-red: extracting addressed neighbors only leaves the 257
    // statements in one serializer graph and reports no lane.
    assert_eq!(stats.neighbor_import_lanes, 1);
    assert_eq!(stats.statements, 257);
    assert_eq!(stats.max_chunk_statements, 256);
    assert_eq!(config, original, "every lane restored in place");
    assert_eq!(
        config.neighbors.interface_only()[0].import_policy.len(),
        257
    );
    assert_eq!(bounded, oracle, "byte-identical to the unbounded render");
}
