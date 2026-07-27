//! `rbgp config import` — golden translations, honesty-report content
//! (skipped stanzas with source line numbers), and the exit-code
//! ladder. The emitted-config `rustbgpd --check` acceptance gate lives
//! in the workspace-root tests (`tests/config_import_emitted_check.rs`)
//! where the daemon binary is available.

use rustbgpctl::importer::{ImportError, SourceFormat, detect_format, import_source, run_import};

const BIRD: &str = include_str!("fixtures/import/bird.conf");
const BIRD_INCLUDES: &str = include_str!("fixtures/import/bird-includes.conf");
const FRR: &str = include_str!("fixtures/import/frr.conf");
const GOBGP: &str = include_str!("fixtures/import/gobgp.toml");

fn skip_lines(report: &rustbgpctl::importer::Report) -> Vec<(Option<usize>, String)> {
    report
        .skipped
        .iter()
        .map(|s| (s.line, s.stanza.clone()))
        .collect()
}

// ---------------------------------------------------------------------------
// Golden translations
// ---------------------------------------------------------------------------

#[test]
fn bird_golden_translation() {
    let imported = import_source(SourceFormat::Bird, "bird.conf", BIRD).expect("translates");
    assert_eq!(
        imported.config_toml,
        include_str!("fixtures/import/expected-bird.toml")
    );
}

#[test]
fn frr_golden_translation() {
    let imported = import_source(SourceFormat::Frr, "frr.conf", FRR).expect("translates");
    assert_eq!(
        imported.config_toml,
        include_str!("fixtures/import/expected-frr.toml")
    );
}

#[test]
fn gobgp_golden_translation() {
    let imported = import_source(SourceFormat::Gobgp, "gobgp.toml", GOBGP).expect("translates");
    assert_eq!(
        imported.config_toml,
        include_str!("fixtures/import/expected-gobgp.toml")
    );
}

// ---------------------------------------------------------------------------
// Honesty report: every untranslated stanza, with source line numbers
// ---------------------------------------------------------------------------

#[test]
fn bird_report_lists_skipped_stanzas_with_lines() {
    let report = import_source(SourceFormat::Bird, "bird.conf", BIRD)
        .expect("translates")
        .report;
    let skips = skip_lines(&report);
    // Filters and filter-adjacent stanzas, each pinned to its source line.
    assert!(
        skips
            .iter()
            .any(|(l, s)| *l == Some(8) && s.starts_with("define OUR_NETS"))
    );
    assert!(
        skips
            .iter()
            .any(|(l, s)| *l == Some(14) && s.contains("protocol static"))
    );
    assert!(
        skips
            .iter()
            .any(|(l, s)| *l == Some(20) && s.contains("filter export_to_upstream"))
    );
    assert!(
        skips
            .iter()
            .any(|(l, s)| *l == Some(53) && s.contains("export where"))
    );
    assert!(
        skips
            .iter()
            .any(|(l, s)| *l == Some(63) && s.contains("import filter"))
    );
    // Filter skips carry the .rpol pointer.
    assert!(
        report
            .skipped
            .iter()
            .filter(|s| s.stanza.contains("filter"))
            .all(|s| s.guidance.contains(".rpol")),
        "filter guidance must point at .rpol"
    );
    // MD5 presence is flagged; the secret itself never appears anywhere.
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("192.0.2.1") && w.contains("MD5"))
    );
    let imported = import_source(SourceFormat::Bird, "bird.conf", BIRD).expect("translates");
    assert!(!imported.config_toml.contains("example-md5-secret"));
    assert_eq!(report.exit_code, 2);
}

/// Load-bearing include-boundary proof: removing the pre-context include
/// intercept changes or loses these diagnostics, including the one inside an
/// otherwise ignored block. Weakening its operator guidance also changes the
/// exact tuples.
#[test]
fn bird_includes_are_reported_from_every_parser_context() {
    const GUIDANCE: &str = "BIRD imports are deliberately single-file; flatten all referenced \
                            files into one source before importing";

    let imported = import_source(SourceFormat::Bird, "bird-includes.conf", BIRD_INCLUDES)
        .expect("translates the available skeleton");
    assert_eq!(imported.report.source_path, "bird-includes.conf");
    let skips = imported
        .report
        .skipped
        .iter()
        .map(|skip| (skip.line, skip.stanza.as_str(), skip.guidance.as_str()))
        .collect::<Vec<_>>();

    assert_eq!(
        skips,
        vec![
            (Some(1), r#"include "conf.d/*.conf""#, GUIDANCE),
            (Some(6), r#"include "peer.conf""#, GUIDANCE),
            (Some(9), r#"include "policy.conf""#, GUIDANCE),
            (Some(15), r#"include "device.conf""#, GUIDANCE),
        ]
    );
    assert_eq!(imported.report.exit_code, 2);
    assert!(imported.report.warnings.is_empty());
    assert_eq!(imported.report.local_asn, 64500);
    assert_eq!(imported.report.router_id, "192.0.2.10");
    assert_eq!(imported.report.neighbor_count, 1);
    assert!(imported.config_toml.contains("address = \"192.0.2.1\""));
    assert!(imported.config_toml.contains("remote_asn = 64496"));
    assert!(
        imported
            .config_toml
            .contains("families = [\"ipv4_unicast\"]")
    );
}

#[test]
fn frr_report_lists_skipped_stanzas_with_lines() {
    let report = import_source(SourceFormat::Frr, "frr.conf", FRR)
        .expect("translates")
        .report;
    let skips = skip_lines(&report);
    assert!(
        skips
            .iter()
            .any(|(l, s)| *l == Some(7) && s.starts_with("ip prefix-list OUR-NETS seq 5"))
    );
    assert!(
        skips
            .iter()
            .any(|(l, s)| *l == Some(8) && s.starts_with("ip prefix-list OUR-NETS seq 10"))
    );
    assert!(
        skips
            .iter()
            .any(|(l, s)| *l == Some(10) && s.starts_with("route-map UPSTREAM-OUT"))
    );
    assert!(
        skips
            .iter()
            .any(|(l, s)| *l == Some(29) && s.starts_with("network 198.51.100.0/24"))
    );
    assert!(
        skips
            .iter()
            .any(|(l, s)| *l == Some(33) && s.contains("route-map UPSTREAM-OUT out"))
    );
    assert!(
        skips
            .iter()
            .any(|(l, s)| *l == Some(41) && s.starts_with("ip route"))
    );
    // Benign daemon boilerplate is not noise in the report.
    assert!(
        !skips
            .iter()
            .any(|(_, s)| s.contains("hostname") || s.contains("frr version"))
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("192.0.2.1") && w.contains("MD5"))
    );
    let imported = import_source(SourceFormat::Frr, "frr.conf", FRR).expect("translates");
    assert!(!imported.config_toml.contains("example-md5-secret"));
    assert_eq!(report.exit_code, 2);
}

#[test]
fn gobgp_report_lists_skipped_stanzas_with_lines() {
    let report = import_source(SourceFormat::Gobgp, "gobgp.toml", GOBGP)
        .expect("translates")
        .report;
    let skips = skip_lines(&report);
    assert!(
        skips
            .iter()
            .any(|(l, s)| l.is_some() && s == "policy-definitions")
    );
    assert!(
        skips
            .iter()
            .any(|(l, s)| l.is_some() && s == "defined-sets")
    );
    assert!(
        skips
            .iter()
            .any(|(l, s)| l.is_some() && s == "global.apply-policy")
    );
    assert!(
        skips
            .iter()
            .any(|(l, s)| l.is_some() && s.contains("192.0.2.200") && s.contains("apply-policy"))
    );
    assert!(skips.iter().any(|(_, s)| s.contains("afi-safi l2vpn-evpn")));
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("192.0.2.1") && w.contains("MD5"))
    );
    let imported = import_source(SourceFormat::Gobgp, "gobgp.toml", GOBGP).expect("translates");
    assert!(!imported.config_toml.contains("example-md5-secret"));
    assert_eq!(report.exit_code, 2);
}

/// The two BIRD spellings that reuse block/statement punctuation inside an
/// expression. Before the scanner tracked bracket and paren depth, the
/// prefix-set ranges split one `define` into one entry per member plus a
/// trailing bare `]`, and the `;`-separated declaration lists split each
/// header into fragments and left the following `{` reported with an empty
/// stanza. Both shapes come straight from ARouteServer-generated output.
const BIRD_EXPRESSION_PUNCTUATION: &str = "\
router id 192.0.2.2;

define bogons = [
\t0.0.0.0/8{8,32},\t# RFC 1122
\t10.0.0.0/8{8,32}\t# RFC 1918
];

function prefix_len_is_valid (int pref_len_min; int pref_len_max)
int set bogon_asns;
{
\treturn true;
}

filter channel_export_ipv4
int i;
{
\taccept;
}

protocol bgp member_alpha {
  local as 999;
  neighbor 192.0.2.11 as 64501;
}
";

#[test]
fn bird_expression_punctuation_reports_one_entry_per_construct() {
    let report = import_source(SourceFormat::Bird, "ars.conf", BIRD_EXPRESSION_PUNCTUATION)
        .expect("translates")
        .report;

    assert!(
        report.skipped.iter().all(|s| !s.stanza.trim().is_empty()),
        "no report entry may have a blank stanza: {:?}",
        skip_lines(&report)
    );
    assert_eq!(
        skip_lines(&report),
        vec![
            (
                Some(3),
                "define bogons = [ 0.0.0.0/8{8,32}, 10.0.0.0/8{8,32} ]".to_owned()
            ),
            (
                Some(8),
                "function prefix_len_is_valid (int pref_len_min; int pref_len_max) int set \
                 bogon_asns"
                    .to_owned()
            ),
            (Some(14), "filter channel_export_ipv4 int i".to_owned()),
        ],
    );
    // A filter/function header that arrived through the statement path is
    // still a filter to hand-translate, not an unknown structural stanza.
    assert!(
        report
            .skipped
            .iter()
            .filter(|s| s.stanza.starts_with("filter") || s.stanza.starts_with("function"))
            .all(|s| s.guidance.contains(".rpol")),
    );
    // The neighbor after all of it still translates: the depth counters must
    // not have swallowed the rest of the file.
    assert_eq!(report.neighbor_count, 1);
}

// ---------------------------------------------------------------------------
// RFC 8212 fail-closed knob in the emitted config
// ---------------------------------------------------------------------------

#[test]
fn emitted_global_fails_closed_and_the_report_says_so() {
    let imported = import_source(SourceFormat::Bird, "bird.conf", BIRD).expect("translates");
    // Inside `[global]`: before the first following section header.
    let global = imported
        .config_toml
        .split("\n[global.telemetry]")
        .next()
        .expect("global section");
    assert!(
        global.contains("\nebgp_requires_policy = true\n"),
        "generated [global] must fail closed: {global}"
    );

    assert!(imported.report.ebgp_requires_policy);
    let text = imported.report.render_text();
    assert!(text.contains("ebgp_requires_policy = true"));
    assert!(
        text.contains("the source config did not ask for"),
        "the report must own the decision, not just mention the knob: {text}"
    );
    assert!(
        text.contains("restart"),
        "the report must say the knob is restart-required: {text}"
    );
}

// ---------------------------------------------------------------------------
// Exit-code ladder
// ---------------------------------------------------------------------------

const CLEAN_FRR: &str = "\
router bgp 64500
 bgp router-id 192.0.2.10
 neighbor 192.0.2.1 remote-as 64496
 neighbor 192.0.2.1 description upstream
 !
 address-family ipv4 unicast
  neighbor 192.0.2.1 activate
 exit-address-family
!
";

#[test]
fn exit_0_clean_full_translation() {
    let imported = import_source(SourceFormat::Frr, "clean.conf", CLEAN_FRR).expect("translates");
    assert!(
        imported.report.skipped.is_empty(),
        "{:?}",
        imported.report.skipped
    );
    assert_eq!(imported.report.exit_code, 0);

    let clean_bird = "router id 192.0.2.10;\n\
                      protocol bgp up { local as 64500; neighbor 192.0.2.1 as 64496; \
                      ipv4 { import all; }; }\n";
    let imported = import_source(SourceFormat::Bird, "clean.conf", clean_bird).expect("translates");
    assert!(
        imported.report.skipped.is_empty(),
        "{:?}",
        imported.report.skipped
    );
    assert_eq!(imported.report.exit_code, 0);

    let clean_gobgp = "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n\
                       [[neighbors]]\n[neighbors.config]\n\
                       neighbor-address = \"192.0.2.1\"\npeer-as = 64496\n";
    let imported =
        import_source(SourceFormat::Gobgp, "clean.toml", clean_gobgp).expect("translates");
    assert!(
        imported.report.skipped.is_empty(),
        "{:?}",
        imported.report.skipped
    );
    assert_eq!(imported.report.exit_code, 0);
}

#[test]
fn exit_1_parse_and_format_errors() {
    let err = import_source(SourceFormat::Gobgp, "x.toml", "not = [valid").unwrap_err();
    assert!(matches!(err, ImportError::Parse(_)));
    assert_eq!(err.exit_code(), 1);

    let err = detect_format("mystery.conf", "hello world\n").unwrap_err();
    assert!(matches!(err, ImportError::Format(_)));
    assert_eq!(err.exit_code(), 1);
}

#[test]
fn exit_2_translated_with_skips() {
    for (format, path, contents) in [
        (SourceFormat::Bird, "bird.conf", BIRD),
        (SourceFormat::Frr, "frr.conf", FRR),
        (SourceFormat::Gobgp, "gobgp.toml", GOBGP),
    ] {
        let imported = import_source(format, path, contents).expect("translates");
        assert!(!imported.report.skipped.is_empty());
        assert_eq!(imported.report.exit_code, 2, "{path}");
    }
}

/// Load-bearing exit-contract proof: a placeholder-bearing translation must
/// require review even when no stanza was skipped. Reverting `Report::exit_code`
/// to inspect only `skipped` makes this return zero.
#[test]
fn exit_2_translated_with_warning_only() {
    let source = "router bgp 64500\n neighbor 192.0.2.1 remote-as 64496\n!\n";
    let imported = import_source(SourceFormat::Frr, "warning.conf", source).expect("translates");
    assert!(imported.report.skipped.is_empty());
    assert!(!imported.report.warnings.is_empty());
    assert_eq!(imported.report.exit_code, 2);
}

#[test]
fn exit_3_refused_when_nothing_translatable() {
    // Valid FRR shape, but no BGP instance at all.
    let err = import_source(SourceFormat::Frr, "x.conf", "hostname r1\nlog syslog\n").unwrap_err();
    assert!(matches!(err, ImportError::Empty(_)), "{err:?}");
    assert_eq!(err.exit_code(), 3);

    // A BGP instance with no translatable neighbors.
    let err = import_source(
        SourceFormat::Frr,
        "x.conf",
        "router bgp 64500\n bgp router-id 192.0.2.1\n",
    )
    .unwrap_err();
    assert!(matches!(err, ImportError::Empty(_)), "{err:?}");
    assert_eq!(err.exit_code(), 3);
}

// ---------------------------------------------------------------------------
// Structural details worth pinning
// ---------------------------------------------------------------------------

#[test]
fn format_detection() {
    assert!(matches!(
        detect_format("a.conf", BIRD),
        Ok(SourceFormat::Bird)
    ));
    assert!(matches!(
        detect_format("a.conf", FRR),
        Ok(SourceFormat::Frr)
    ));
    assert!(matches!(
        detect_format("a.toml", GOBGP),
        Ok(SourceFormat::Gobgp)
    ));
    // Extension wins for TOML even without [global.config] on top.
    assert!(matches!(
        detect_format("b.toml", "x = 1\n"),
        Ok(SourceFormat::Gobgp)
    ));
}

#[test]
fn group_remote_as_resolves_onto_members() {
    // FRR: remote-as on the peer-group only.
    let imported = import_source(SourceFormat::Frr, "frr.conf", FRR).expect("translates");
    assert!(
        imported
            .config_toml
            .contains("address = \"192.0.2.1\"\nremote_asn = 64496")
    );
    // GoBGP: peer-as on the peer-group only.
    let imported = import_source(SourceFormat::Gobgp, "gobgp.toml", GOBGP).expect("translates");
    assert!(
        imported
            .config_toml
            .contains("address = \"192.0.2.200\"\nremote_asn = 64499")
    );
}

/// Load-bearing FRR-default proof: removing the additive default-IPv4
/// post-pass leaves this explicitly IPv6-activated peer with IPv6 only,
/// contrary to FRR's default AF semantics.
#[test]
fn frr_default_ipv4_is_additive_to_explicit_ipv6() {
    let source = "\
router bgp 64500
 bgp router-id 192.0.2.10
 neighbor 192.0.2.1 remote-as 64496
 address-family ipv6 unicast
  neighbor 192.0.2.1 activate
 exit-address-family
!
";
    let imported = import_source(SourceFormat::Frr, "dual.conf", source).expect("translates");
    assert!(
        imported
            .config_toml
            .contains("families = [\"ipv6_unicast\", \"ipv4_unicast\"]"),
        "{}",
        imported.config_toml
    );
}

/// Load-bearing instance-boundary proof: accepting suffix tokens on the first
/// `router bgp` line imports a VRF as rustbgpd's global instance and causes the
/// real global instance below it to be discarded.
#[test]
fn frr_vrf_instance_is_not_imported_as_global() {
    let source = "\
router bgp 65100 vrf BLUE
 bgp router-id 198.51.100.1
 neighbor 198.51.100.2 remote-as 65101
!
router bgp 64500
 bgp router-id 192.0.2.10
 neighbor 192.0.2.1 remote-as 64496
!
";
    let imported = import_source(SourceFormat::Frr, "vrf.conf", source).expect("translates");
    assert_eq!(imported.report.local_asn, 64500);
    assert_eq!(imported.report.neighbor_count, 1);
    assert!(imported.config_toml.contains("address = \"192.0.2.1\""));
    assert!(!imported.config_toml.contains("198.51.100.2"));
    assert!(
        imported
            .report
            .skipped
            .iter()
            .any(|skip| skip.stanza == "router bgp 65100 vrf BLUE")
    );
}

/// Load-bearing numeric-boundary proof: Rust's float-to-integer cast saturates,
/// so removing the explicit upper bound silently turns this invalid GoBGP AS
/// into 4294967295 instead of refusing the source.
#[test]
fn gobgp_rejects_out_of_range_float_asn() {
    let source = "\
[global.config]
as = 1e100
router-id = \"192.0.2.10\"
[[neighbors]]
[neighbors.config]
neighbor-address = \"192.0.2.1\"
peer-as = 64496
";
    let error = import_source(SourceFormat::Gobgp, "overflow.toml", source).unwrap_err();
    assert!(matches!(error, ImportError::Empty(_)), "{error:?}");
}

// ---------------------------------------------------------------------------
// Fail-closed on fields the daemon's `--check` rejects: a config the
// daemon refuses wholesale must never leave the importer with exit 0.
// ---------------------------------------------------------------------------

#[test]
fn unparseable_router_id_warns_in_every_frontend() {
    for (format, path, source, bad) in [
        (
            SourceFormat::Frr,
            "frr-badrid.conf",
            "router bgp 64500\n bgp router-id 2001:db8::1\n neighbor 192.0.2.1 remote-as 64496\n!\n",
            "2001:db8::1",
        ),
        (
            SourceFormat::Bird,
            "bird-badrid.conf",
            "router id fe80::1;\nprotocol bgp up { local as 64500; \
             neighbor 192.0.2.1 as 64496; }\n",
            "fe80::1",
        ),
        (
            SourceFormat::Gobgp,
            "gobgp-badrid.toml",
            "[global.config]\nas = 64500\nrouter-id = \"not-an-ip\"\n[[neighbors]]\n\
             [neighbors.config]\nneighbor-address = \"192.0.2.1\"\npeer-as = 64496\n",
            "not-an-ip",
        ),
        // The daemon also refuses the unspecified address.
        (
            SourceFormat::Frr,
            "frr-zerorid.conf",
            "router bgp 64500\n bgp router-id 0.0.0.0\n neighbor 192.0.2.1 remote-as 64496\n!\n",
            "0.0.0.0",
        ),
    ] {
        let imported = import_source(format, path, source).expect("translates");
        assert_eq!(imported.report.exit_code, 2, "{path}");
        assert!(
            imported
                .report
                .warnings
                .iter()
                .any(|w| w.contains("router-id") && w.contains(bad) && w.contains("--check")),
            "{path}: {:?}",
            imported.report.warnings
        );
    }
}

#[test]
fn dangling_peer_group_reference_warns_in_every_frontend() {
    for (format, path, source, group) in [
        (
            SourceFormat::Frr,
            "frr-dangling.conf",
            "router bgp 64500\n bgp router-id 192.0.2.10\n \
             neighbor 192.0.2.1 remote-as 64496\n \
             neighbor 192.0.2.1 peer-group CORE\n!\n",
            "CORE",
        ),
        (
            SourceFormat::Bird,
            "bird-dangling.conf",
            "router id 192.0.2.10;\nprotocol bgp up from missing_tmpl { local as 64500; \
             neighbor 192.0.2.1 as 64496; }\n",
            "missing_tmpl",
        ),
        (
            SourceFormat::Gobgp,
            "gobgp-dangling.toml",
            "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n[[neighbors]]\n\
             [neighbors.config]\nneighbor-address = \"192.0.2.1\"\npeer-as = 64496\n\
             peer-group = \"CORE\"\n",
            "CORE",
        ),
    ] {
        let imported = import_source(format, path, source).expect("translates");
        assert_eq!(imported.report.exit_code, 2, "{path}");
        assert!(
            imported
                .report
                .warnings
                .iter()
                .any(|w| w.contains("192.0.2.1") && w.contains(group) && w.contains("--check")),
            "{path}: {:?}",
            imported.report.warnings
        );
    }
}

// ---------------------------------------------------------------------------
// Out-of-range numerics are reported, never silently dropped
// ---------------------------------------------------------------------------

#[test]
fn gobgp_out_of_range_hold_time_warns_and_is_not_emitted() {
    let source = "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n[[neighbors]]\n\
                  [neighbors.config]\nneighbor-address = \"192.0.2.1\"\npeer-as = 64496\n\
                  [neighbors.timers.config]\nhold-time = 70000\n";
    let imported = import_source(SourceFormat::Gobgp, "hold.toml", source).expect("translates");
    assert!(!imported.config_toml.contains("hold_time"));
    assert_eq!(imported.report.exit_code, 2);
    assert!(
        imported
            .report
            .warnings
            .iter()
            .any(|w| w.contains("hold-time") && w.contains("70000")),
        "{:?}",
        imported.report.warnings
    );
}

#[test]
fn gobgp_out_of_range_peer_as_warns_alongside_the_skip() {
    let source = "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n[[neighbors]]\n\
                  [neighbors.config]\nneighbor-address = \"192.0.2.1\"\npeer-as = 64496\n\
                  [[neighbors]]\n[neighbors.config]\n\
                  neighbor-address = \"192.0.2.2\"\npeer-as = 4294967296\n";
    let imported = import_source(SourceFormat::Gobgp, "peeras.toml", source).expect("translates");
    assert_eq!(imported.report.exit_code, 2);
    assert!(
        imported
            .report
            .warnings
            .iter()
            .any(|w| w.contains("peer-as") && w.contains("4294967296")),
        "{:?}",
        imported.report.warnings
    );
    // The undeterminable neighbor still lands on the skip ladder.
    assert!(
        imported
            .report
            .skipped
            .iter()
            .any(|s| s.stanza.contains("192.0.2.2"))
    );
}

#[test]
fn gobgp_out_of_range_local_as_is_named_in_the_refusal() {
    let source = "[global.config]\nas = 4294967296\nrouter-id = \"192.0.2.10\"\n[[neighbors]]\n\
                  [neighbors.config]\nneighbor-address = \"192.0.2.1\"\npeer-as = 64496\n";
    let error = import_source(SourceFormat::Gobgp, "localas.toml", source).unwrap_err();
    assert!(matches!(error, ImportError::Empty(_)), "{error:?}");
    let rendered = error.to_string();
    assert!(
        rendered.contains("global.config.as") && rendered.contains("4294967296"),
        "the refusal must name the dropped field and value: {rendered}"
    );
}

#[test]
fn gobgp_out_of_range_max_prefixes_warns() {
    let source = "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n[[neighbors]]\n\
                  [neighbors.config]\nneighbor-address = \"192.0.2.1\"\npeer-as = 64496\n\
                  [[neighbors.afi-safis]]\n[neighbors.afi-safis.config]\n\
                  afi-safi-name = \"ipv4-unicast\"\n\
                  [neighbors.afi-safis.prefix-limit.config]\nmax-prefixes = -5\n";
    let imported = import_source(SourceFormat::Gobgp, "maxpfx.toml", source).expect("translates");
    assert!(!imported.config_toml.contains("max_prefixes"));
    assert_eq!(imported.report.exit_code, 2);
    assert!(
        imported
            .report
            .warnings
            .iter()
            .any(|w| w.contains("max-prefixes") && w.contains("-5")),
        "{:?}",
        imported.report.warnings
    );
}

#[test]
fn frr_unparseable_keepalive_warns_instead_of_skipping_the_ratio_check() {
    let source = "router bgp 64500\n bgp router-id 192.0.2.10\n \
                  neighbor 192.0.2.1 remote-as 64496\n \
                  neighbor 192.0.2.1 timers garbage 180\n!\n";
    let imported = import_source(SourceFormat::Frr, "keepalive.conf", source).expect("translates");
    assert_eq!(imported.report.exit_code, 2);
    assert!(
        imported
            .report
            .warnings
            .iter()
            .any(|w| w.contains("keepalive") && w.contains("garbage")),
        "{:?}",
        imported.report.warnings
    );
}

/// BIRD numeric parse failures already land on the skip ladder; pin it.
#[test]
fn bird_out_of_range_hold_time_lands_on_the_skip_ladder() {
    let source = "router id 192.0.2.10;\nprotocol bgp up { local as 64500; \
                  neighbor 192.0.2.1 as 64496; hold time 70000; }\n";
    let imported = import_source(SourceFormat::Bird, "hold.conf", source).expect("translates");
    assert_eq!(imported.report.exit_code, 2);
    assert!(
        imported
            .report
            .skipped
            .iter()
            .any(|s| s.stanza.contains("hold time 70000")),
        "{:?}",
        imported.report.skipped
    );
    assert!(!imported.config_toml.contains("hold_time"));
}

#[test]
fn keepalive_mismatch_is_warned_never_guessed() {
    for (format, path, contents, needle) in [
        (SourceFormat::Bird, "bird.conf", BIRD, "upstream2"),
        (SourceFormat::Frr, "frr.conf", FRR, "2001:db8::1"),
        (SourceFormat::Gobgp, "gobgp.toml", GOBGP, "2001:db8::1"),
    ] {
        let report = import_source(format, path, contents)
            .expect("translates")
            .report;
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains(needle) && w.contains("hold_time/3")),
            "{path}: {:?}",
            report.warnings
        );
    }
}

// ---------------------------------------------------------------------------
// run_import (the CLI surface): I/O paths of the ladder
// ---------------------------------------------------------------------------

#[test]
fn run_import_missing_file_is_exit_1() {
    assert_eq!(run_import("/nonexistent/x.conf", None, None, false), 1);
}

#[test]
fn run_import_json_requires_out() {
    assert_eq!(run_import("/nonexistent/x.conf", None, None, true), 1);
}

#[test]
fn run_import_writes_config_and_exits_2_on_skips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("frr.conf");
    std::fs::write(&source, FRR).expect("write source");
    let out = dir.path().join("config.toml");
    let code = run_import(
        source.to_str().expect("utf8"),
        None,
        Some(out.to_str().expect("utf8")),
        false,
    );
    assert_eq!(code, 2);
    let written = std::fs::read_to_string(&out).expect("config written");
    assert_eq!(written, include_str!("fixtures/import/expected-frr.toml"));
}
