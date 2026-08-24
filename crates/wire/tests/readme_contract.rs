use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use syn::{
    Attribute, Expr, FnArg, GenericArgument, Item, Lit, Meta, PathArguments, ReturnType, Type,
    UseTree, Visibility,
};

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
    let syntax = syn::parse_file(source).expect("message.rs must remain valid Rust");
    let Some(function) = syntax.items.iter().find_map(|item| match item {
        Item::Fn(function)
            if function.sig.ident == "decode_message" && is_public(&function.vis) =>
        {
            Some(function)
        }
        _ => None,
    }) else {
        return false;
    };
    let mut inputs = function.sig.inputs.iter();
    let first_is_bytes = inputs.next().is_some_and(|argument| {
        matches!(argument, FnArg::Typed(argument) if is_mut_reference_to(&argument.ty, "Bytes"))
    });
    let second_is_u16 = inputs.next().is_some_and(
        |argument| matches!(argument, FnArg::Typed(argument) if is_plain_type(&argument.ty, "u16")),
    );
    first_is_bytes
        && second_is_u16
        && inputs.next().is_none()
        && return_type_is_result(&function.sig.output, "Message", "DecodeError")
}

fn is_plain_type(ty: &Type, name: &str) -> bool {
    matches!(
        ty,
        Type::Path(path)
            if path.qself.is_none()
                && path.path.leading_colon.is_none()
                && path.path.segments.len() == 1
                && path.path.segments[0].ident == name
                && matches!(path.path.segments[0].arguments, PathArguments::None)
    )
}

fn is_mut_reference_to(ty: &Type, name: &str) -> bool {
    matches!(ty, Type::Reference(reference) if reference.mutability.is_some() && is_plain_type(&reference.elem, name))
}

fn return_type_is_result(output: &ReturnType, ok: &str, error: &str) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };
    let Type::Path(path) = ty.as_ref() else {
        return false;
    };
    if path.qself.is_some() || path.path.segments.len() != 1 {
        return false;
    }
    let result = &path.path.segments[0];
    let PathArguments::AngleBracketed(arguments) = &result.arguments else {
        return false;
    };
    let mut arguments = arguments.args.iter();
    result.ident == "Result"
        && arguments.next().is_some_and(
            |argument| matches!(argument, GenericArgument::Type(ty) if is_plain_type(ty, ok)),
        )
        && arguments.next().is_some_and(
            |argument| matches!(argument, GenericArgument::Type(ty) if is_plain_type(ty, error)),
        )
        && arguments.next().is_none()
}

fn use_tree_imports_from(
    tree: &UseTree,
    source: &str,
    source_name: &str,
    local_name: &str,
) -> bool {
    let mut uses = Vec::new();
    flatten_use_tree(tree, &mut Vec::new(), &mut uses);
    uses.iter().any(|public_use| {
        matches!(
            public_use,
            PublicUse::Named {
                source: item_source,
                local,
            } if item_source == &[source, source_name] && local == local_name
        )
    })
}

fn use_tree_binds_name(tree: &UseTree, local_name: &str) -> bool {
    match tree {
        UseTree::Path(path) => use_tree_binds_name(path.tree.as_ref(), local_name),
        UseTree::Name(item) => item.ident == local_name,
        UseTree::Rename(item) => item.rename == local_name,
        UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_binds_name(item, local_name)),
        UseTree::Glob(_) => false,
    }
}

fn message_imports_bytes_type(source: &str) -> bool {
    syn::parse_file(source)
        .expect("message.rs must remain valid Rust")
        .items
        .iter()
        .any(|item| {
            matches!(item, Item::Use(item_use) if use_tree_imports_from(&item_use.tree, "bytes", "Bytes", "Bytes"))
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
    let codec_modules = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(item_mod) if item_mod.ident == "tokio_codec" && is_public(&item_mod.vis) => {
                Some(item_mod)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let codec_bindings = syntax
        .items
        .iter()
        .filter(|item| match item {
            Item::Use(item_use) => {
                is_public(&item_use.vis) && use_tree_binds_name(&item_use.tree, "BgpCodecError")
            }
            Item::Enum(item) => item.ident == "BgpCodecError" && is_public(&item.vis),
            Item::Struct(item) => item.ident == "BgpCodecError" && is_public(&item.vis),
            Item::Type(item) => item.ident == "BgpCodecError" && is_public(&item.vis),
            Item::Union(item) => item.ident == "BgpCodecError" && is_public(&item.vis),
            Item::Trait(item) => item.ident == "BgpCodecError" && is_public(&item.vis),
            Item::TraitAlias(item) => item.ident == "BgpCodecError" && is_public(&item.vis),
            Item::Fn(item) => item.sig.ident == "BgpCodecError" && is_public(&item.vis),
            Item::Const(item) => item.ident == "BgpCodecError" && is_public(&item.vis),
            Item::Static(item) => item.ident == "BgpCodecError" && is_public(&item.vis),
            Item::Mod(item) => item.ident == "BgpCodecError" && is_public(&item.vis),
            Item::ExternCrate(item) => {
                is_public(&item.vis)
                    && item
                        .rename
                        .as_ref()
                        .is_some_and(|(_, name)| name == "BgpCodecError")
            }
            _ => false,
        })
        .collect::<Vec<_>>();

    codec_modules.len() == 1
        && has_feature_gate(&codec_modules[0].attrs, "tokio-codec")
        && codec_bindings.len() == 1
        && !root_public_glob_may_bind(source, "BgpCodecError")
        && matches!(
            codec_bindings[0],
            Item::Use(item_use)
                if has_feature_gate(&item_use.attrs, "tokio-codec")
                    && use_tree_imports_from(
                        &item_use.tree,
                        "tokio_codec",
                        "BgpCodecError",
                        "BgpCodecError",
                    )
        )
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
    Module(Vec<String>),
    NamedItem,
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

fn merge_module_inventory(target: &mut ModuleInventory, incoming: ModuleInventory) {
    // The source graph intentionally sees every cfg branch. Mutually exclusive declarations of
    // one logical module therefore contribute a conservative all-configuration union here.
    for (name, export) in incoming.direct_exports {
        target.direct_exports.entry(name).or_insert(export);
    }
    target.public_uses.extend(incoming.public_uses);
    target.public_children.extend(incoming.public_children);
    target.public_children.sort();
    target.public_children.dedup();
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
            Item::Enum(item_enum) if is_public(&item_enum.vis) => {
                let name = item_enum.ident.to_string();
                let export =
                    if has_non_exhaustive_attribute(&item_enum.attrs) && name.ends_with("Error") {
                        let mut qualified = vec!["rustbgpd_wire".to_string()];
                        qualified.extend_from_slice(module_path);
                        qualified.push(name.clone());
                        PublicExport::Error(qualified.join("::"))
                    } else {
                        PublicExport::NamedItem
                    };
                inventory.direct_exports.insert(name, export);
            }
            Item::Struct(item_struct) if is_public(&item_struct.vis) => {
                inventory
                    .direct_exports
                    .insert(item_struct.ident.to_string(), PublicExport::NamedItem);
            }
            Item::Union(item_union) if is_public(&item_union.vis) => {
                inventory
                    .direct_exports
                    .insert(item_union.ident.to_string(), PublicExport::NamedItem);
            }
            Item::Trait(item_trait) if is_public(&item_trait.vis) => {
                inventory
                    .direct_exports
                    .insert(item_trait.ident.to_string(), PublicExport::NamedItem);
            }
            Item::TraitAlias(item_alias) if is_public(&item_alias.vis) => {
                inventory
                    .direct_exports
                    .insert(item_alias.ident.to_string(), PublicExport::NamedItem);
            }
            Item::Fn(item_fn) if is_public(&item_fn.vis) => {
                inventory
                    .direct_exports
                    .insert(item_fn.sig.ident.to_string(), PublicExport::NamedItem);
            }
            Item::Const(item_const) if is_public(&item_const.vis) => {
                inventory
                    .direct_exports
                    .insert(item_const.ident.to_string(), PublicExport::NamedItem);
            }
            Item::Static(item_static) if is_public(&item_static.vis) => {
                inventory
                    .direct_exports
                    .insert(item_static.ident.to_string(), PublicExport::NamedItem);
            }
            Item::ExternCrate(item_extern) if is_public(&item_extern.vis) => {
                let local = item_extern.rename.as_ref().map_or_else(
                    || item_extern.ident.to_string(),
                    |(_, name)| name.to_string(),
                );
                let export = if item_extern.ident == "bytes" {
                    PublicExport::BytesDependency
                } else {
                    PublicExport::NamedItem
                };
                inventory.direct_exports.insert(local, export);
            }
            Item::Use(item_use) if is_public(&item_use.vis) => {
                flatten_use_tree(&item_use.tree, &mut Vec::new(), &mut inventory.public_uses);
            }
            Item::Type(item_type) if is_public(&item_type.vis) => {
                inventory
                    .direct_exports
                    .insert(item_type.ident.to_string(), PublicExport::NamedItem);
                if let Type::Path(type_path) = item_type.ty.as_ref()
                    && type_path.qself.is_none()
                {
                    inventory.public_uses.push(PublicUse::Named {
                        source: type_path
                            .path
                            .segments
                            .iter()
                            .map(|segment| segment.ident.to_string())
                            .collect(),
                        local: item_type.ident.to_string(),
                    });
                }
            }
            Item::Mod(item_mod) => {
                let name = item_mod.ident.to_string();
                let mut child_path = module_path.to_vec();
                child_path.push(name.clone());
                let child_directory = module_directory.join(&name);
                if is_public(&item_mod.vis) {
                    inventory.public_children.push(child_path.clone());
                    inventory
                        .direct_exports
                        .insert(name.clone(), PublicExport::Module(child_path.clone()));
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
    if let Some(existing) = modules.get_mut(module_path) {
        merge_module_inventory(existing, inventory);
    } else {
        modules.insert(module_path.to_vec(), inventory);
    }
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

fn resolve_module_path(
    exports: &BTreeMap<Vec<String>, BTreeMap<String, PublicExport>>,
    path: &[String],
) -> Option<Vec<String>> {
    let mut resolved = Vec::new();
    for segment in path {
        let mut physical_child = resolved.clone();
        physical_child.push(segment.clone());
        if exports.contains_key(&physical_child) {
            resolved = physical_child;
            continue;
        }
        let PublicExport::Module(alias_target) = exports.get(&resolved)?.get(segment)? else {
            return None;
        };
        resolved.clone_from(alias_target);
    }
    Some(resolved)
}

fn resolve_export_path(
    exports: &BTreeMap<Vec<String>, BTreeMap<String, PublicExport>>,
    path: &[String],
) -> Option<PublicExport> {
    let (name, module_path) = path.split_last()?;
    let resolved_module = resolve_module_path(exports, module_path)?;
    exports.get(&resolved_module)?.get(name).cloned()
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
                        if let Some(export) = resolve_export_path(&snapshot, &absolute) {
                            changed |= module_exports
                                .insert(local.clone(), export.clone())
                                .as_ref()
                                != Some(&export);
                        }
                    }
                    PublicUse::Glob { source } => {
                        let absolute = absolute_use_path(module_path, source);
                        if let Some(target) = resolve_module_path(&snapshot, &absolute)
                            .and_then(|target| snapshot.get(&target))
                        {
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

fn root_public_glob_may_bind(source: &str, name: &str) -> bool {
    let syntax = syn::parse_file(source).expect("lib.rs must remain valid Rust");
    let source_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut modules = BTreeMap::new();
    inspect_module_items(&syntax.items, &[], &source_directory, &mut modules);
    let exports = resolved_module_exports(&modules);
    modules
        .get(&Vec::new())
        .expect("root module was inspected")
        .public_uses
        .iter()
        .filter_map(|public_use| match public_use {
            PublicUse::Glob { source } => Some(source),
            PublicUse::Named { .. } => None,
        })
        .any(|source| {
            let absolute = absolute_use_path(&[], source);
            let Some(target) = resolve_module_path(&exports, &absolute) else {
                return true;
            };
            exports
                .get(&target)
                .is_none_or(|module| module.contains_key(name))
        })
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
            for export in exports
                .get(&module_path)
                .expect("reachable module has resolved exports")
                .values()
            {
                if let PublicExport::Module(child) = export {
                    changed |= reachable.insert(child.clone());
                }
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
            PublicExport::BytesDependency | PublicExport::Module(_) | PublicExport::NamedItem => {
                None
            }
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
    let wrong_limit_type =
        MESSAGE_SOURCE.replacen("max_message_len: u16", "max_message_len: u32", 1);
    assert!(!decode_message_has_bytes_signature(&wrong_limit_type));
    let wrong_return = MESSAGE_SOURCE.replacen(
        "Result<Message, DecodeError>",
        "Result<Message, EncodeError>",
        1,
    );
    assert!(!decode_message_has_bytes_signature(&wrong_return));
    let stale_signature_comment = r#"
        // pub fn decode_message(buf: &mut Bytes, max_message_len: u16) -> Result<Message, DecodeError>
        pub fn decode_message(
            _buf: &mut Vec<u8>,
            _max_message_len: u16,
        ) -> Result<Message, DecodeError> {
            unimplemented!()
        }
    "#;
    assert!(!decode_message_has_bytes_signature(stale_signature_comment));
    let wrong_bytes_source =
        MESSAGE_SOURCE.replacen("use bytes::{Bytes, BytesMut};", "type Bytes = Vec<u8>;", 1);
    assert!(!message_imports_bytes_type(&wrong_bytes_source));
    let aliased_bytes_source = MESSAGE_SOURCE.replacen(
        "use bytes::{Bytes, BytesMut};",
        "use bytes::{Bytes as DependencyBytes, BytesMut};\ntype Bytes = Vec<u8>;",
        1,
    );
    assert!(!message_imports_bytes_type(&aliased_bytes_source));
    let wrong_source_item = MESSAGE_SOURCE.replacen(
        "use bytes::{Bytes, BytesMut};",
        "use bytes::{Bytes as DependencyBytes, BytesMut as Bytes};",
        1,
    );
    assert!(!message_imports_bytes_type(&wrong_source_item));

    for reexport in [
        "pub use bytes::Bytes;",
        "pub use {bytes::Bytes};",
        "pub extern crate bytes;",
        "pub type WireBytes = bytes::Bytes;",
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
    let wrong_codec_source_item = r#"
        #[cfg(feature = "tokio-codec")]
        pub mod tokio_codec { pub struct BgpCodec; pub enum BgpCodecError {} }
        #[cfg(feature = "tokio-codec")]
        pub use tokio_codec::BgpCodec as BgpCodecError;
    "#;
    assert!(!lib_exposes_codec_only_behind_feature(
        wrong_codec_source_item
    ));
    let alternative_ungated_binding = r#"
        #[cfg(feature = "tokio-codec")]
        pub mod tokio_codec { pub enum BgpCodecError {} }
        #[cfg(feature = "tokio-codec")]
        pub use tokio_codec::BgpCodecError;
        #[cfg(not(feature = "tokio-codec"))]
        pub use error::DecodeError as BgpCodecError;
    "#;
    assert!(!lib_exposes_codec_only_behind_feature(
        alternative_ungated_binding
    ));
    let glob_alternative_binding = r#"
        #[cfg(feature = "tokio-codec")]
        pub mod tokio_codec { pub enum BgpCodecError {} }
        #[cfg(feature = "tokio-codec")]
        pub use tokio_codec::BgpCodecError;
        #[cfg(not(feature = "tokio-codec"))]
        mod fallback {
            pub struct BgpCodecError;
        }
        #[cfg(not(feature = "tokio-codec"))]
        pub use fallback::*;
    "#;
    assert!(!lib_exposes_codec_only_behind_feature(
        glob_alternative_binding
    ));
    let unrelated_glob = r#"
        #[cfg(feature = "tokio-codec")]
        pub mod tokio_codec { pub enum BgpCodecError {} }
        #[cfg(feature = "tokio-codec")]
        pub use tokio_codec::BgpCodecError;
        mod additional { pub struct OtherPublicType; }
        pub use additional::*;
    "#;
    assert!(lib_exposes_codec_only_behind_feature(unrelated_glob));

    let exhaustiveness = section(README, "## Enum exhaustiveness");
    for name in ERROR_ENUM_NAMES {
        let missing_name = exhaustiveness.replacen(&format!("`{name}`"), "`RemovedError`", 1);
        assert!(!has_documented_error_roster(&missing_name));
    }

    for name in ERROR_ENUM_NAMES {
        assert!(
            source_enum_is_public_and_non_exhaustive(
                &format!("#[derive(Debug)]\n#[non_exhaustive]\npub enum {name} {{ Example }}"),
                name,
            ),
            "structural checker must accept reordered attributes for {name}"
        );
        assert!(!source_enum_is_public_and_non_exhaustive(
            &format!("pub enum {name} {{ Example }}"),
            name
        ));
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

    let private_module_facade = r#"
        mod hidden {
            pub mod api {
                #[non_exhaustive]
                pub enum FutureError { Example }
                pub use bytes::Bytes;
            }
        }
        pub use hidden::api;
    "#;
    let (module_errors, module_bytes) = inline_source_inventory(private_module_facade);
    assert_eq!(module_errors, ["rustbgpd_wire::hidden::api::FutureError"]);
    assert_eq!(module_bytes, ["rustbgpd_wire::hidden::api"]);

    let chained_module_facade = r#"
        mod hidden {
            mod deeper {
                pub mod api {
                    #[non_exhaustive]
                    pub enum FutureError { Example }
                    pub use bytes::Bytes;
                }
            }
            pub use self::deeper::api as facade;
            pub use self::facade::{Bytes, FutureError};
        }
        pub use hidden::{Bytes, FutureError};
    "#;
    let (chained_errors, chained_bytes) = inline_source_inventory(chained_module_facade);
    assert_eq!(
        chained_errors,
        ["rustbgpd_wire::hidden::deeper::api::FutureError"]
    );
    assert_eq!(chained_bytes, ["rustbgpd_wire"]);

    let cfg_exclusive_modules = r#"
        #[cfg(unix)]
        pub mod platform {
            #[non_exhaustive]
            pub enum UnixError { Example }
        }
        #[cfg(windows)]
        pub mod platform {
            #[non_exhaustive]
            pub enum WindowsError { Example }
        }
    "#;
    let (cfg_errors, cfg_bytes) = inline_source_inventory(cfg_exclusive_modules);
    assert_eq!(
        cfg_errors,
        [
            "rustbgpd_wire::platform::UnixError",
            "rustbgpd_wire::platform::WindowsError",
        ],
        "cfg-exclusive declarations of one logical module must form an all-config union"
    );
    assert!(cfg_bytes.is_empty());
}
