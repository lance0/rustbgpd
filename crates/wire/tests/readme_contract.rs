use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use syn::{Attribute, Expr, Item, Lit, Meta, UseTree, Visibility};

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
        UseTree::Rename(item) => item.rename == name,
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
    syn::parse_file(source)
        .expect("error source must remain valid Rust")
        .items
        .iter()
        .any(|item| {
            matches!(
                item,
                Item::Enum(item_enum)
                    if item_enum.ident == name
                        && is_public(&item_enum.vis)
                        && has_non_exhaustive_attribute(&item_enum.attrs)
            )
        })
}

fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

fn has_non_exhaustive_attribute(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("non_exhaustive"))
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

fn lib_exposes_codec_only_behind_feature(source: &str) -> bool {
    let syntax = syn::parse_file(source).expect("lib.rs must remain valid Rust");
    let module_is_gated = syntax.items.iter().any(|item| {
        matches!(
            item,
            Item::Mod(item_mod)
                if item_mod.ident == "tokio_codec"
                    && is_public(&item_mod.vis)
                    && has_feature_gate(&item_mod.attrs, "tokio-codec")
        )
    });
    let root_reexport_is_gated = syntax.items.iter().any(|item| {
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
    });
    module_is_gated && root_reexport_is_gated
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

fn explicit_module_path(attributes: &[Attribute], module_directory: &Path) -> Option<PathBuf> {
    attributes.iter().find_map(|attribute| {
        let Meta::NameValue(name_value) = &attribute.meta else {
            return None;
        };
        if !attribute.path().is_ident("path") {
            return None;
        }
        let Expr::Lit(expr_lit) = &name_value.value else {
            return None;
        };
        let Lit::Str(path) = &expr_lit.lit else {
            return None;
        };
        Some(module_directory.join(path.value()))
    })
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PublicExport {
    Error(String),
    BytesDependency,
}

#[derive(Clone, Debug)]
enum PublicUse {
    Named { source: Vec<String>, local: String },
    Glob { source: Vec<String> },
}

#[derive(Default)]
struct ModuleInventory {
    direct_exports: BTreeMap<String, PublicExport>,
    public_uses: Vec<PublicUse>,
    public_children: Vec<Vec<String>>,
}

fn flatten_use_tree(tree: &UseTree, prefix: &mut Vec<String>, uses: &mut Vec<PublicUse>) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use_tree(path.tree.as_ref(), prefix, uses);
            prefix.pop();
        }
        UseTree::Name(name) => {
            let mut source = prefix.clone();
            source.push(name.ident.to_string());
            uses.push(PublicUse::Named {
                local: name.ident.to_string(),
                source,
            });
        }
        UseTree::Rename(rename) => {
            let mut source = prefix.clone();
            source.push(rename.ident.to_string());
            uses.push(PublicUse::Named {
                local: rename.rename.to_string(),
                source,
            });
        }
        UseTree::Glob(_) => uses.push(PublicUse::Glob {
            source: prefix.clone(),
        }),
        UseTree::Group(group) => {
            for item in &group.items {
                flatten_use_tree(item, prefix, uses);
            }
        }
    }
}

fn inspect_module_items(
    items: &[Item],
    module_path: &[String],
    module_directory: &Path,
    modules: &mut BTreeMap<Vec<String>, ModuleInventory>,
) {
    let mut inventory = ModuleInventory::default();
    for item in items {
        match item {
            Item::Enum(item_enum)
                if is_public(&item_enum.vis)
                    && has_non_exhaustive_attribute(&item_enum.attrs)
                    && item_enum.ident.to_string().ends_with("Error") =>
            {
                let name = item_enum.ident.to_string();
                let mut qualified = vec!["rustbgpd_wire".to_string()];
                qualified.extend_from_slice(module_path);
                qualified.push(name.clone());
                inventory
                    .direct_exports
                    .insert(name, PublicExport::Error(qualified.join("::")));
            }
            Item::ExternCrate(item_extern)
                if is_public(&item_extern.vis) && item_extern.ident == "bytes" =>
            {
                let local = item_extern
                    .rename
                    .as_ref()
                    .map_or_else(|| "bytes".to_string(), |(_, name)| name.to_string());
                inventory
                    .direct_exports
                    .insert(local, PublicExport::BytesDependency);
            }
            Item::Use(item_use) if is_public(&item_use.vis) => {
                flatten_use_tree(&item_use.tree, &mut Vec::new(), &mut inventory.public_uses);
            }
            Item::Mod(item_mod) => {
                let name = item_mod.ident.to_string();
                let mut child_path = module_path.to_vec();
                child_path.push(name.clone());
                let child_directory = module_directory.join(&name);
                if is_public(&item_mod.vis) {
                    inventory.public_children.push(child_path.clone());
                }
                if let Some((_, child_items)) = &item_mod.content {
                    inspect_module_items(child_items, &child_path, &child_directory, modules);
                } else {
                    inspect_module_file(
                        &explicit_module_path(&item_mod.attrs, module_directory)
                            .unwrap_or_else(|| external_module_path(module_directory, &name)),
                        &child_path,
                        &child_directory,
                        modules,
                    );
                }
            }
            _ => {}
        }
    }
    assert!(
        modules.insert(module_path.to_vec(), inventory).is_none(),
        "duplicate module path {module_path:?}"
    );
}

fn inspect_module_file(
    source_path: &Path,
    module_path: &[String],
    module_directory: &Path,
    modules: &mut BTreeMap<Vec<String>, ModuleInventory>,
) {
    let source = std::fs::read_to_string(source_path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", source_path.display()));
    let syntax = syn::parse_file(&source)
        .unwrap_or_else(|error| panic!("cannot parse {}: {error}", source_path.display()));
    inspect_module_items(&syntax.items, module_path, module_directory, modules);
}

fn absolute_use_path(current_module: &[String], source: &[String]) -> Vec<String> {
    let mut source = source;
    let mut absolute = Vec::new();
    if source.first().is_some_and(|segment| segment == "crate") {
        source = &source[1..];
    } else if source.first().is_some_and(|segment| segment == "self") {
        absolute.extend_from_slice(current_module);
        source = &source[1..];
    } else if source.first().is_some_and(|segment| segment == "super") {
        absolute.extend_from_slice(current_module);
        while source.first().is_some_and(|segment| segment == "super") {
            absolute.pop();
            source = &source[1..];
        }
    }
    absolute.extend_from_slice(source);
    absolute
}

fn resolved_module_exports(
    modules: &BTreeMap<Vec<String>, ModuleInventory>,
) -> BTreeMap<Vec<String>, BTreeMap<String, PublicExport>> {
    let mut exports = modules
        .iter()
        .map(|(path, module)| (path.clone(), module.direct_exports.clone()))
        .collect::<BTreeMap<_, _>>();

    loop {
        let snapshot = exports.clone();
        let mut changed = false;
        for (module_path, module) in modules {
            let module_exports = exports
                .get_mut(module_path)
                .expect("every parsed module has an export map");
            for public_use in &module.public_uses {
                match public_use {
                    PublicUse::Named { source, local }
                        if source.first().is_some_and(|part| part == "bytes") =>
                    {
                        changed |= module_exports
                            .insert(local.clone(), PublicExport::BytesDependency)
                            .as_ref()
                            != Some(&PublicExport::BytesDependency);
                    }
                    PublicUse::Glob { source }
                        if source.first().is_some_and(|part| part == "bytes") =>
                    {
                        changed |= module_exports
                            .insert("*bytes".to_string(), PublicExport::BytesDependency)
                            .as_ref()
                            != Some(&PublicExport::BytesDependency);
                    }
                    PublicUse::Named { source, local } => {
                        let absolute = absolute_use_path(module_path, source);
                        let Some((name, target_module)) = absolute.split_last() else {
                            continue;
                        };
                        if let Some(export) = snapshot
                            .get(target_module)
                            .and_then(|target| target.get(name))
                        {
                            changed |= module_exports
                                .insert(local.clone(), export.clone())
                                .as_ref()
                                != Some(export);
                        }
                    }
                    PublicUse::Glob { source } => {
                        let absolute = absolute_use_path(module_path, source);
                        if let Some(target) = snapshot.get(&absolute) {
                            for (name, export) in target {
                                changed |=
                                    module_exports.insert(name.clone(), export.clone()).as_ref()
                                        != Some(export);
                            }
                        }
                    }
                }
            }
        }
        if !changed {
            return exports;
        }
    }
}

fn inventory_from_modules(
    modules: &BTreeMap<Vec<String>, ModuleInventory>,
) -> (Vec<String>, Vec<String>) {
    let exports = resolved_module_exports(modules);
    let mut reachable = BTreeSet::from([Vec::<String>::new()]);
    loop {
        let mut changed = false;
        for module_path in reachable.clone() {
            let module = modules
                .get(&module_path)
                .expect("reachable module was parsed");
            for child in &module.public_children {
                changed |= reachable.insert(child.clone());
            }
        }
        if !changed {
            break;
        }
    }

    let mut errors = BTreeSet::new();
    let mut bytes_reexports = Vec::new();
    for module_path in reachable {
        let module_exports = exports.get(&module_path).expect("reachable export map");
        if module_exports
            .values()
            .any(|export| matches!(export, PublicExport::BytesDependency))
        {
            let mut qualified = vec!["rustbgpd_wire".to_string()];
            qualified.extend(module_path.clone());
            bytes_reexports.push(qualified.join("::"));
        }
        errors.extend(module_exports.values().filter_map(|export| match export {
            PublicExport::Error(name) => Some(name.clone()),
            PublicExport::BytesDependency => None,
        }));
    }
    (errors.into_iter().collect(), bytes_reexports)
}

fn public_api_source_inventory() -> (Vec<String>, Vec<String>) {
    let source_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut modules = BTreeMap::new();
    inspect_module_file(
        &source_directory.join("lib.rs"),
        &[],
        &source_directory,
        &mut modules,
    );
    inventory_from_modules(&modules)
}

fn inline_source_inventory(source: &str) -> (Vec<String>, Vec<String>) {
    let syntax = syn::parse_file(source).expect("mutation source must be valid Rust");
    let mut modules = BTreeMap::new();
    inspect_module_items(
        &syntax.items,
        &[],
        Path::new("unused-for-inline-modules"),
        &mut modules,
    );
    inventory_from_modules(&modules)
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
        lib_exposes_codec_only_behind_feature(LIB_SOURCE),
        "the tokio_codec module and root BgpCodecError binding must remain feature-gated"
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
    let aliased_bytes_source = MESSAGE_SOURCE.replacen(
        "use bytes::{Bytes, BytesMut};",
        "use bytes::{Bytes as DependencyBytes, BytesMut};\ntype Bytes = Vec<u8>;",
        1,
    );
    assert!(!message_imports_bytes_type(&aliased_bytes_source));

    for reexport in [
        "pub use bytes::Bytes;",
        "pub use {bytes::Bytes};",
        "pub extern crate bytes;",
    ] {
        assert!(
            !inline_source_inventory(reexport).1.is_empty(),
            "inventory must detect {reexport}"
        );
    }

    let reordered_codec_reexport = r#"
        #[cfg(feature = "tokio-codec")]
        pub mod tokio_codec { pub struct BgpCodec; pub enum BgpCodecError {} }
        #[cfg(feature = "tokio-codec")]
        pub use tokio_codec::{BgpCodecError, BgpCodec};
    "#;
    assert!(lib_exposes_codec_only_behind_feature(
        reordered_codec_reexport
    ));
    let ungated_codec_module = r#"
        pub mod tokio_codec { pub enum BgpCodecError {} }
        #[cfg(feature = "tokio-codec")]
        pub use tokio_codec::BgpCodecError;
    "#;
    assert!(!lib_exposes_codec_only_behind_feature(ungated_codec_module));

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

    let mutations = r#"
        pub mod future {
            #[non_exhaustive]
            #[derive(Debug)]
            pub enum FutureError { Example }
        }
        pub mod distinct {
            #[non_exhaustive]
            pub enum DecodeError { DistinctModuleVariant }
        }
        mod private {
            #[non_exhaustive]
            pub enum PrivateError { Example }
        }
    "#;
    let (errors, bytes_reexports) = inline_source_inventory(mutations);
    assert_eq!(
        errors,
        [
            "rustbgpd_wire::distinct::DecodeError",
            "rustbgpd_wire::future::FutureError",
        ],
        "inventory must retain qualified duplicates, accept intervening attributes, and ignore private modules"
    );
    assert!(bytes_reexports.is_empty());

    let private_facade = r#"
        mod hidden {
            #[non_exhaustive]
            pub enum FutureError { Example }
            pub use bytes::Bytes;
        }
        pub use hidden::{Bytes, FutureError};
    "#;
    let (facade_errors, facade_bytes) = inline_source_inventory(private_facade);
    assert_eq!(facade_errors, ["rustbgpd_wire::hidden::FutureError"]);
    assert_eq!(facade_bytes, ["rustbgpd_wire"]);
}
