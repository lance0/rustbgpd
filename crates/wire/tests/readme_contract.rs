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
}
