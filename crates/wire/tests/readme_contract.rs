use std::path::{Path, PathBuf};

use syn::{Attribute, Item, ItemExternCrate, ItemUse, Meta, UseTree, Visibility};

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

fn use_tree_contains_name(tree: &UseTree, name: &str) -> bool {
    match tree {
        UseTree::Path(path) => use_tree_contains_name(path.tree.as_ref(), name),
        UseTree::Name(item) => item.ident == name,
        UseTree::Rename(item) => item.ident == name,
        UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_contains_name(item, name)),
        UseTree::Glob(_) => false,
    }
}

fn use_tree_imports_from(tree: &UseTree, source: &str, name: &str) -> bool {
    matches!(tree, UseTree::Path(path) if path.ident == source && use_tree_contains_name(path.tree.as_ref(), name))
}

fn message_imports_bytes_type(source: &str) -> bool {
    syn::parse_file(source)
        .expect("message.rs must remain valid Rust")
        .items
        .iter()
        .any(|item| {
            matches!(item, Item::Use(item_use) if use_tree_imports_from(&item_use.tree, "bytes", "Bytes"))
        })
}

fn source_enum_is_public_and_non_exhaustive(source: &str, name: &str) -> bool {
    compact_whitespace(source).contains(&format!("#[non_exhaustive] pub enum {name}"))
}

fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

fn has_non_exhaustive_attribute(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("non_exhaustive"))
}

fn use_tree_mentions_bytes(tree: &UseTree) -> bool {
    match tree {
        UseTree::Path(path) => path.ident == "bytes" || use_tree_mentions_bytes(path.tree.as_ref()),
        UseTree::Name(name) => name.ident == "bytes",
        UseTree::Rename(rename) => rename.ident == "bytes",
        UseTree::Group(group) => group.items.iter().any(use_tree_mentions_bytes),
        UseTree::Glob(_) => false,
    }
}

fn public_item_reexports_bytes(item: &Item) -> bool {
    match item {
        Item::Use(ItemUse { vis, tree, .. }) => is_public(vis) && use_tree_mentions_bytes(tree),
        Item::ExternCrate(ItemExternCrate { vis, ident, .. }) => is_public(vis) && ident == "bytes",
        _ => false,
    }
}

fn has_feature_gate(attributes: &[Attribute], feature: &str) -> bool {
    attributes.iter().any(|attribute| {
        let Meta::List(list) = &attribute.meta else {
            return false;
        };
        attribute.path().is_ident("cfg")
            && compact_whitespace(&list.tokens.to_string()) == format!("feature = \"{feature}\"")
    })
}

fn lib_reexports_codec_error_behind_feature(source: &str) -> bool {
    syn::parse_file(source)
        .expect("lib.rs must remain valid Rust")
        .items
        .iter()
        .any(|item| {
            matches!(
                item,
                Item::Use(item_use)
                    if is_public(&item_use.vis)
                        && has_feature_gate(&item_use.attrs, "tokio-codec")
                        && use_tree_imports_from(
                            &item_use.tree,
                            "tokio_codec",
                            "BgpCodecError",
                        )
            )
        })
}

fn external_module_path(module_directory: &Path, name: &str) -> PathBuf {
    let sibling = module_directory.join(format!("{name}.rs"));
    if sibling.is_file() {
        sibling
    } else {
        let nested = module_directory.join(name).join("mod.rs");
        assert!(
            nested.is_file(),
            "cannot resolve public module {name:?} below {}",
            module_directory.display()
        );
        nested
    }
}

fn inspect_public_items(
    items: &[Item],
    module_path: &str,
    module_directory: &Path,
    errors: &mut Vec<String>,
    bytes_reexports: &mut Vec<String>,
) {
    for item in items {
        if public_item_reexports_bytes(item) {
            bytes_reexports.push(module_path.to_string());
        }

        match item {
            Item::Enum(item_enum)
                if is_public(&item_enum.vis)
                    && has_non_exhaustive_attribute(&item_enum.attrs)
                    && item_enum.ident.to_string().ends_with("Error") =>
            {
                errors.push(format!("{module_path}::{}", item_enum.ident));
            }
            Item::Mod(item_mod) if is_public(&item_mod.vis) => {
                let name = item_mod.ident.to_string();
                let child_path = format!("{module_path}::{name}");
                let child_directory = module_directory.join(&name);
                if let Some((_, child_items)) = &item_mod.content {
                    inspect_public_items(
                        child_items,
                        &child_path,
                        &child_directory,
                        errors,
                        bytes_reexports,
                    );
                } else {
                    inspect_public_module(
                        &external_module_path(module_directory, &name),
                        &child_path,
                        &child_directory,
                        errors,
                        bytes_reexports,
                    );
                }
            }
            _ => {}
        }
    }
}

fn inspect_public_module(
    source_path: &Path,
    module_path: &str,
    module_directory: &Path,
    errors: &mut Vec<String>,
    bytes_reexports: &mut Vec<String>,
) {
    let source = std::fs::read_to_string(source_path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", source_path.display()));
    let syntax = syn::parse_file(&source)
        .unwrap_or_else(|error| panic!("cannot parse {}: {error}", source_path.display()));
    inspect_public_items(
        &syntax.items,
        module_path,
        module_directory,
        errors,
        bytes_reexports,
    );
}

fn public_api_source_inventory() -> (Vec<String>, Vec<String>) {
    let source_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut errors = Vec::new();
    let mut bytes_reexports = Vec::new();
    inspect_public_module(
        &source_directory.join("lib.rs"),
        "rustbgpd_wire",
        &source_directory,
        &mut errors,
        &mut bytes_reexports,
    );
    errors.sort();
    bytes_reexports.sort();
    (errors, bytes_reexports)
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
        message_imports_bytes_type(MESSAGE_SOURCE),
        "decode_message's Bytes type must be imported from the bytes crate"
    );
    let (_, bytes_reexports) = public_api_source_inventory();
    assert!(
        bytes_reexports.is_empty(),
        "README says bytes is not re-exported, but public modules re-export it: {bytes_reexports:?}"
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

    assert!(
        lib_reexports_codec_error_behind_feature(LIB_SOURCE),
        "BgpCodecError must remain publicly re-exported behind the tokio-codec feature"
    );
}

#[test]
fn enum_exhaustiveness_roster_covers_every_public_error_enum() {
    let mut expected = [
        "rustbgpd_wire::error::DecodeError",
        "rustbgpd_wire::error::EncodeError",
        "rustbgpd_wire::evpn::RouteDistinguisherParseError",
        "rustbgpd_wire::notification::ShutdownCommunicationError",
        "rustbgpd_wire::tokio_codec::BgpCodecError",
    ]
    .map(str::to_string)
    .to_vec();
    expected.sort();
    let (errors, _) = public_api_source_inventory();
    assert_eq!(
        errors, expected,
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
    let wrong_bytes_source =
        MESSAGE_SOURCE.replacen("use bytes::{Bytes, BytesMut};", "type Bytes = Vec<u8>;", 1);
    assert!(!message_imports_bytes_type(&wrong_bytes_source));

    for reexport in [
        "pub use bytes::Bytes;",
        "pub use {bytes::Bytes};",
        "pub extern crate bytes;",
    ] {
        let item = syn::parse_str::<Item>(reexport).expect("valid public re-export mutation");
        assert!(
            public_item_reexports_bytes(&item),
            "inventory must detect {reexport}"
        );
    }

    let reordered_codec_reexport = r#"
        #[cfg(feature = "tokio-codec")]
        pub use tokio_codec::{BgpCodecError, BgpCodec};
    "#;
    assert!(lib_reexports_codec_error_behind_feature(
        reordered_codec_reexport
    ));
    let ungated_codec_reexport = "pub use tokio_codec::BgpCodecError;";
    assert!(!lib_reexports_codec_error_behind_feature(
        ungated_codec_reexport
    ));

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

    let future_errors =
        syn::parse_file("#[non_exhaustive]\n#[derive(Debug)]\npub enum FutureError { Example }")
            .expect("valid future error mutation");
    let duplicate_name =
        syn::parse_file("#[non_exhaustive]\npub enum DecodeError { DistinctModuleVariant }")
            .expect("valid duplicate-name mutation");
    let private_nested =
        syn::parse_file("mod private { #[non_exhaustive] pub enum PrivateError { Example } }")
            .expect("valid private-module control");
    let mut errors = Vec::new();
    let mut bytes_reexports = Vec::new();
    for (syntax, module_path) in [
        (&future_errors, "rustbgpd_wire::future"),
        (&duplicate_name, "rustbgpd_wire::distinct"),
        (&private_nested, "rustbgpd_wire"),
    ] {
        inspect_public_items(
            &syntax.items,
            module_path,
            Path::new("unused-for-inline-modules"),
            &mut errors,
            &mut bytes_reexports,
        );
    }
    errors.sort();
    assert_eq!(
        errors,
        [
            "rustbgpd_wire::distinct::DecodeError",
            "rustbgpd_wire::future::FutureError",
        ],
        "inventory must retain qualified duplicates, accept intervening attributes, and ignore private modules"
    );
}
