use std::path::{Path, PathBuf};

const README: &str = include_str!("../README.md");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const MESSAGE_SOURCE: &str = include_str!("../src/message.rs");
const ERROR_ENUM_NAMES: [&str; 5] = [
    "DecodeError",
    "EncodeError",
    "RouteDistinguisherParseError",
    "ShutdownCommunicationError",
    "BgpCodecError",
];

fn section<'a>(document: &'a str, heading: &str) -> &'a str {
    let start = document
        .find(heading)
        .unwrap_or_else(|| panic!("missing README section {heading:?}"));
    let body = &document[start + heading.len()..];
    let end = body.find("\n## ").unwrap_or(body.len());
    &body[..end]
}

fn compact_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn expected_dependency_block(version: &str) -> String {
    format!("```toml\n[dependencies]\nrustbgpd-wire = \"{version}\"\nbytes = \"1\"\n```")
}

fn has_documented_error_roster(exhaustiveness: &str) -> bool {
    compact_whitespace(exhaustiveness).contains(
        "The five public error enums are also non-exhaustive: `DecodeError`, `EncodeError`, \
         `RouteDistinguisherParseError`, `ShutdownCommunicationError`, and `BgpCodecError` \
         (available with the `tokio-codec` feature).",
    )
}

fn decode_message_has_bytes_signature(source: &str) -> bool {
    compact_whitespace(source).contains(
        "pub fn decode_message(buf: &mut Bytes, max_message_len: u16) -> Result<Message, DecodeError>",
    )
}

fn source_enum_is_public_and_non_exhaustive(source: &str, name: &str) -> bool {
    compact_whitespace(source).contains(&format!("#[non_exhaustive] pub enum {name}"))
}

fn error_enums_in_source(source: &str) -> Vec<String> {
    let compact = compact_whitespace(source);
    let marker = "#[non_exhaustive] pub enum ";
    let mut remainder = compact.as_str();
    let mut names = Vec::new();
    while let Some(offset) = remainder.find(marker) {
        let declaration = &remainder[offset + marker.len()..];
        let end = declaration
            .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .unwrap_or(declaration.len());
        let name = &declaration[..end];
        if name.ends_with("Error") {
            names.push(name.to_string());
        }
        remainder = &declaration[end..];
    }
    names
}

fn collect_rust_sources(directory: &Path, paths: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
    {
        let path = entry.expect("source directory entry").path();
        if path.is_dir() {
            collect_rust_sources(&path, paths);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            paths.push(path);
        }
    }
}

fn public_non_exhaustive_error_enum_roster() -> Vec<String> {
    let mut paths = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut paths,
    );
    let mut names = paths
        .iter()
        .flat_map(|path| {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            error_enums_in_source(&source)
        })
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn public_bytes_reexports(source: &str) -> Vec<&str> {
    source
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("pub use bytes") || line.starts_with("pub extern crate bytes")
        })
        .collect()
}

#[test]
fn usage_pins_direct_dependencies_to_the_published_wire_version() {
    let usage = section(README, "## Usage");
    let dependency_block = expected_dependency_block(env!("CARGO_PKG_VERSION"));

    assert!(
        usage.contains(&dependency_block),
        "Usage must pin rustbgpd-wire to the package version and bytes to major version 1"
    );
    assert!(
        usage.contains("`decode_message` accepts `&mut bytes::Bytes`"),
        "Usage must name the public buffer type accepted by decode_message"
    );
    assert!(
        usage.contains("it is not re-exported"),
        "Usage must explain why downstream consumers need a direct bytes dependency"
    );
}

#[test]
fn decode_entry_point_keeps_the_documented_bytes_contract() {
    assert!(
        decode_message_has_bytes_signature(MESSAGE_SOURCE),
        "decode_message no longer has the documented &mut bytes::Bytes signature"
    );
    assert!(
        public_bytes_reexports(LIB_SOURCE).is_empty(),
        "README says bytes is not re-exported, but lib.rs contains a public bytes re-export"
    );
}

#[test]
fn enum_exhaustiveness_names_the_complete_public_error_roster() {
    let exhaustiveness = section(README, "## Enum exhaustiveness");

    assert!(
        has_documented_error_roster(exhaustiveness),
        "Enum exhaustiveness must name the exact five-enum roster and identify BgpCodecError as feature-gated"
    );
    assert!(
        exhaustiveness.contains("must include\na wildcard arm"),
        "Enum exhaustiveness must preserve downstream wildcard guidance"
    );
    assert!(
        exhaustiveness.contains("_ => {}"),
        "Enum exhaustiveness must retain its wildcard match example"
    );
}

#[test]
fn every_documented_public_error_enum_stays_non_exhaustive_in_source() {
    let declarations = [
        (include_str!("../src/error.rs"), "DecodeError"),
        (include_str!("../src/error.rs"), "EncodeError"),
        (
            include_str!("../src/evpn.rs"),
            "RouteDistinguisherParseError",
        ),
        (
            include_str!("../src/notification.rs"),
            "ShutdownCommunicationError",
        ),
        (include_str!("../src/tokio_codec.rs"), "BgpCodecError"),
    ];

    for (source, name) in declarations {
        assert!(
            source_enum_is_public_and_non_exhaustive(source, name),
            "{name} must remain a public #[non_exhaustive] enum"
        );
    }

    let compact_lib = compact_whitespace(LIB_SOURCE);
    assert!(
        compact_lib.contains(
            "#[cfg(feature = \"tokio-codec\")] pub use tokio_codec::{BgpCodec, BgpCodecError};"
        ),
        "BgpCodecError must remain publicly re-exported behind the tokio-codec feature"
    );
}

#[test]
fn enum_exhaustiveness_roster_covers_every_public_error_enum() {
    let mut expected = ERROR_ENUM_NAMES.map(str::to_string).to_vec();
    expected.sort();
    assert_eq!(
        public_non_exhaustive_error_enum_roster(),
        expected,
        "README roster must change whenever the public non-exhaustive error inventory changes"
    );
}

#[test]
fn contract_helpers_reject_independent_documentation_and_source_mutations() {
    let usage = section(README, "## Usage");
    let wrong_version = usage.replace(
        &format!("rustbgpd-wire = \"{}\"", env!("CARGO_PKG_VERSION")),
        "rustbgpd-wire = \"0.0.0\"",
    );
    assert!(!wrong_version.contains(&expected_dependency_block(env!("CARGO_PKG_VERSION"))));

    let wrong_buffer = MESSAGE_SOURCE.replacen("buf: &mut Bytes", "buf: Bytes", 1);
    assert!(!decode_message_has_bytes_signature(&wrong_buffer));

    let reexported_bytes = format!("{LIB_SOURCE}\npub use bytes::Bytes;");
    assert_eq!(
        public_bytes_reexports(&reexported_bytes),
        ["pub use bytes::Bytes;"]
    );

    let exhaustiveness = section(README, "## Enum exhaustiveness");
    for name in ERROR_ENUM_NAMES {
        let missing_name = exhaustiveness.replacen(&format!("`{name}`"), "`RemovedError`", 1);
        assert!(!has_documented_error_roster(&missing_name));
    }

    let declarations = [
        (include_str!("../src/error.rs"), "DecodeError"),
        (include_str!("../src/error.rs"), "EncodeError"),
        (
            include_str!("../src/evpn.rs"),
            "RouteDistinguisherParseError",
        ),
        (
            include_str!("../src/notification.rs"),
            "ShutdownCommunicationError",
        ),
        (include_str!("../src/tokio_codec.rs"), "BgpCodecError"),
    ];
    for (source, name) in declarations {
        let exhaustive = source.replacen(
            &format!("#[non_exhaustive]\npub enum {name}"),
            &format!("pub enum {name}"),
            1,
        );
        assert!(!source_enum_is_public_and_non_exhaustive(&exhaustive, name));
    }

    assert_eq!(
        error_enums_in_source("#[non_exhaustive]\npub enum FutureError { Example }"),
        ["FutureError"],
        "the inventory helper must detect a newly added public error enum"
    );
}
