use rs_config_render::{
    Options, RenderError, SiteLocalFile, SiteLocalInput, render, render_site_local,
};
use sha2::{Digest, Sha256};

const FIXTURE: &str = include_str!("fixtures/context-small.yml");

fn healthy_context() -> String {
    let mut value: serde_yaml::Value = serde_yaml::from_str(FIXTURE).unwrap();
    value["clients"]
        .as_sequence_mut()
        .unwrap()
        .retain(|client| client["id"].as_str() != Some("AS51325_1"));
    value["irrdb_info"]
        .as_mapping_mut()
        .unwrap()
        .remove(serde_yaml::Value::String("AS51325_bundle".into()));
    serde_yaml::to_string(&value).unwrap()
}

fn opts() -> Options {
    Options {
        rtr_caches: vec!["127.0.0.1:3323".into()],
        ..Options::default()
    }
}

fn file(path: &str, source: &str) -> SiteLocalFile {
    SiteLocalFile {
        source_path: path.into(),
        bytes: source.as_bytes().to_vec(),
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn input(merge: &str, policies: &[(&str, &str)]) -> SiteLocalInput {
    SiteLocalInput {
        merge: file("merge.toml", merge),
        policies: policies
            .iter()
            .map(|(path, source)| file(path, source))
            .collect(),
    }
}

fn refused(merge: &str, policies: &[(&str, &str)]) -> String {
    match render_site_local(&healthy_context(), &opts(), &input(merge, policies)) {
        Err(RenderError::Refused(items)) => items.join("\n"),
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[test]
fn exact_bytes_chains_and_receipt_are_load_bearing() {
    assert!(
        render(&healthy_context(), &opts())
            .unwrap()
            .receipt
            .get("site_local")
            .is_none(),
        "the no-flags receipt shape must remain unchanged"
    );
    let first = "policy global-deny {\r\n  term stop { reject }\r\n}";
    let second = "policy peer-tag { term tag { add community 65000:100; accept } }";
    let merge = r#"
[policy]
import_chain = ["global-deny"]
export_chain = ["peer-tag"]

[[neighbors]]
address = "192.0.2.11"
import_policy_chain = ["peer-tag"]
export_policy_chain = ["global-deny"]
"#;
    let rendered = render_site_local(
        &healthy_context(),
        &opts(),
        &input(merge, &[("global.rpol", first), ("peer.rpol", second)]),
    )
    .unwrap();
    assert_eq!(
        rendered.files["policy/site-local-001.rpol"].as_bytes(),
        first.as_bytes()
    );
    assert_eq!(
        rendered.files["policy/site-local-002.rpol"].as_bytes(),
        second.as_bytes()
    );
    let config = &rendered.files["config.toml"];
    assert!(config.contains("\"policy/client-as197000-1.rpol\",\n    \"policy/site-local-001.rpol\",\n    \"policy/site-local-002.rpol\",\n]"));
    assert!(config.contains(
        "import_policy_chain = [\"rs-hygiene\", \"global-deny\", \"peer-tag\", \"client-as4242-1\"]"
    ));
    assert!(config.contains(
        "export_policy_chain = [\"peer-tag\", \"global-deny\", \"rs-transparent-export\"]"
    ));
    assert!(config.contains(
        "import_policy_chain = [\"rs-hygiene\", \"global-deny\", \"client-as197000-1\"]"
    ));
    assert!(config.contains("export_policy_chain = [\"peer-tag\", \"rs-transparent-export\"]"));
    assert!(config.contains("export_chain = [\"rs-transparent-export\"]"));
    let site = &rendered.receipt["site_local"];
    assert_eq!(site["merge_source"]["path"], "merge.toml");
    assert_eq!(site["extra_policies"].as_array().unwrap().len(), 2);
    assert_eq!(
        site["declared_policy_roster"],
        serde_json::json!(["global-deny", "peer-tag"])
    );
    assert_eq!(
        site["flattened_policy_roster"],
        serde_json::json!(["global-deny", "peer-tag"])
    );
    for digest in [
        site["merge_source"]["sha256"].as_str().unwrap(),
        site["extra_policies"][0]["source_sha256"].as_str().unwrap(),
        site["extra_policies"][0]["emitted_sha256"]
            .as_str()
            .unwrap(),
        site["config_sha256"].as_str().unwrap(),
    ] {
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
    assert_eq!(
        site["extra_policies"][0]["source_sha256"],
        site["extra_policies"][0]["emitted_sha256"]
    );
    assert_eq!(site["merge_source"]["sha256"], digest(merge.as_bytes()));
    assert_eq!(
        site["extra_policies"][0]["source_sha256"],
        digest(first.as_bytes())
    );
    assert_eq!(
        site["extra_policies"][0]["emitted_sha256"],
        digest(rendered.files["policy/site-local-001.rpol"].as_bytes())
    );
    assert_eq!(site["config_sha256"], digest(config.as_bytes()));
    assert_eq!(
        site["requested"]["policy"]["import_chain"],
        serde_json::json!(["global-deny"])
    );
    assert_eq!(
        site["final_neighbors"],
        serde_json::json!([
            {"address":"192.0.2.11","import_policy_chain":["rs-hygiene","global-deny","peer-tag","client-as4242-1"],"export_policy_chain":["peer-tag","global-deny","rs-transparent-export"]},
            {"address":"2001:db8:0:1::22","import_policy_chain":["rs-hygiene","global-deny","client-as197000-1"],"export_policy_chain":["peer-tag","rs-transparent-export"]}
        ])
    );
}

#[test]
fn blackhole_base_stays_final() {
    let mut value: serde_yaml::Value = serde_yaml::from_str(&healthy_context()).unwrap();
    value["cfg"]["blackhole_filtering"]["policy_ipv4"] = "propagate-unchanged".into();
    let context = serde_yaml::to_string(&value).unwrap();
    let rendered = render_site_local(
        &context,
        &opts(),
        &input(
            "[policy]\nexport_chain=[\"tag\"]",
            &[(
                "tag.rpol",
                "policy tag { term t { add community 65000:1; accept } }",
            )],
        ),
    )
    .unwrap();
    assert!(
        rendered.files["config.toml"]
            .contains("export_policy_chain = [\"tag\", \"rs-blackhole-export-1\"]")
    );
}

#[test]
fn policy_and_merge_refusal_matrix() {
    let safe = "policy safe { term t { reject } }";
    let cases = [
        (
            "blackhole add",
            "policy p { term t { add community BLACKHOLE; accept } }",
        ),
        (
            "blackhole add",
            "policy p { term t { add community 65535:666 } }",
        ),
        (
            "community removal",
            "policy p { term t { remove community 65000:1; accept } }",
        ),
        (
            "next-hop",
            "policy p { term t { set next-hop self; accept } }",
        ),
        (
            "AS prepend",
            "policy p { term t { prepend as 65001 2; accept } }",
        ),
        (
            "AS prepend",
            "policy p { term t { prepend as self 2; accept } }",
        ),
        (
            "next-hop",
            "policy helper { term t { set next-hop self; accept } } policy p { term t { if apply(helper) { reject } accept } }",
        ),
        (
            "blackhole add",
            "asn-set s { 1 } policy p { term t { for a in s { for b in s { add community BLACKHOLE } } accept } }",
        ),
        (
            "community variables",
            "policy p { term t { for c in route.communities { add community c } accept } }",
        ),
        (
            "imports",
            "import \"other.rpol\"\npolicy p { term t { reject } }",
        ),
        (
            "datasets",
            "dataset asn-set d\npolicy p { term t { reject } }",
        ),
        (
            "datasets",
            "dataset asn-set d\npolicy p { term t { if route.origin-as in d { reject } } }",
        ),
        ("parameters", "policy p(n: u32) { term t { reject } }"),
        ("generated", "policy rs-hygiene { term t { reject } }"),
    ];
    for (needle, source) in cases {
        let message = refused("[policy]\nimport_chain=[\"p\"]", &[("bad.rpol", source)]);
        assert!(message.contains(needle), "{needle}: {message}");
    }
    for (kind, marker, action) in [
        ("std", "65500:666", "add community 65500:666"),
        ("lrg", "65500:666:1", "add large-community 65500:666:1"),
        ("ext", "RT:65000:666", "add ext-community RT:65000:666"),
        ("ext", "RO:65000:667", "add ext-community RO:65000:667"),
        (
            "ext",
            "RT:192.0.2.1:668",
            "add ext-community RT:192.0.2.1:668",
        ),
    ] {
        let mut context: serde_yaml::Value = serde_yaml::from_str(&healthy_context()).unwrap();
        context["cfg"]["communities"]["blackholing"][kind] = marker.into();
        let source = format!("policy p {{ term t {{ {action}; accept }} }}");
        let result = render_site_local(
            &serde_yaml::to_string(&context).unwrap(),
            &opts(),
            &input("[policy]\nimport_chain=[\"p\"]", &[("bad.rpol", &source)]),
        );
        assert!(
            matches!(result, Err(RenderError::Refused(ref items)) if items.iter().any(|item| item.contains("local marker add"))),
            "{kind} {marker}: {result:?}"
        );
    }
    render_site_local(
        &healthy_context(),
        &opts(),
        &input(
            "[policy]\nimport_chain=[\"p\"]",
            &[(
                "safe.rpol",
                "policy p { term t { set local-pref route.med + 1; set med 10; accept } }",
            )],
        ),
    )
    .expect("literal and computed local-pref/MED remain confined");
    let duplicate = refused(
        "[policy]\nimport_chain=[\"same\"]",
        &[
            ("a.rpol", "policy same { term t { reject } }"),
            ("b.rpol", "policy same { term t { reject } }"),
        ],
    );
    assert!(duplicate.contains("duplicate policy"), "{duplicate}");

    let merges = [
        (
            "unknown field `unsafe`",
            "unsafe = true\n[policy]\nimport_chain=[\"safe\"]",
        ),
        ("invalid merge TOML", "[policy"),
        (
            "unknown policy hook",
            "[policy]\nimport_chain=[\"missing\"]",
        ),
        ("unused", "[policy]\nimport_chain=[]"),
        (
            "duplicate hook",
            "[policy]\nimport_chain=[\"safe\",\"safe\"]",
        ),
        (
            "malformed neighbor",
            "[[neighbors]]\naddress=\"not-an-ip\"\nimport_policy_chain=[\"safe\"]",
        ),
        (
            "unknown neighbor",
            "[[neighbors]]\naddress=\"192.0.2.99\"\nimport_policy_chain=[\"safe\"]",
        ),
        (
            "generated policy",
            "[policy]\nimport_chain=[\"rs-hygiene\"]",
        ),
    ];
    for (needle, merge) in merges {
        let message = refused(merge, &[("safe.rpol", safe)]);
        assert!(message.contains(needle), "{needle}: {message}");
    }
    let duplicate_neighbor = refused(
        "[[neighbors]]\naddress=\"192.0.2.11\"\nimport_policy_chain=[\"safe\"]\n[[neighbors]]\naddress=\"192.0.2.11\"",
        &[("safe.rpol", safe)],
    );
    assert!(
        duplicate_neighbor.contains("duplicate neighbor"),
        "{duplicate_neighbor}"
    );
    let composed = refused(
        "[policy]\nimport_chain=[\"safe\"]\n[[neighbors]]\naddress=\"192.0.2.11\"\nimport_policy_chain=[\"safe\"]",
        &[("safe.rpol", safe)],
    );
    assert!(composed.contains("duplicate hook"), "{composed}");
}

#[test]
fn cli_flag_and_fail_stale_matrix() {
    let temp = tempfile::tempdir().unwrap();
    let context = temp.path().join("context.yml");
    let merge = temp.path().join("merge.toml");
    let policy = temp.path().join("site.rpol");
    std::fs::write(&context, healthy_context()).unwrap();
    std::fs::write(&merge, "[policy]\nimport_chain=[\"missing\"]").unwrap();
    std::fs::write(&policy, "policy safe { term t { reject } }").unwrap();
    for (name, args) in [
        ("extra-only", vec!["--extra-rpol", policy.to_str().unwrap()]),
        ("merge-only", vec!["--merge-toml", merge.to_str().unwrap()]),
        (
            "repeated-merge",
            vec![
                "--extra-rpol",
                policy.to_str().unwrap(),
                "--merge-toml",
                merge.to_str().unwrap(),
                "--merge-toml",
                merge.to_str().unwrap(),
            ],
        ),
        (
            "validation",
            vec![
                "--extra-rpol",
                policy.to_str().unwrap(),
                "--merge-toml",
                merge.to_str().unwrap(),
            ],
        ),
    ] {
        let out = temp.path().join(name);
        std::fs::create_dir(&out).unwrap();
        let sentinel = out.join("sentinel");
        std::fs::write(&sentinel, b"keep\0exact").unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
            .args([
                "--context",
                context.to_str().unwrap(),
                "--out-dir",
                out.to_str().unwrap(),
                "--rtr-cache",
                "127.0.0.1:3323",
            ])
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{name}: {output:?}");
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep\0exact");
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1, "{name}");
    }
}
