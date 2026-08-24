use syn::{
    Attribute, FnArg, GenericArgument, GenericParam, Item, Meta, PathArguments, ReturnType, Type,
    UseTree, Visibility,
};

const README: &str = include_str!("../README.md");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const MESSAGE_SOURCE: &str = include_str!("../src/message.rs");
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

fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
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

fn return_type_is_result(output: &ReturnType, ok: &str, error: &str) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };
    let Type::Path(path) = ty.as_ref() else {
        return false;
    };
    let Some(result) = path.path.segments.first() else {
        return false;
    };
    let PathArguments::AngleBracketed(arguments) = &result.arguments else {
        return false;
    };
    let mut arguments = arguments.args.iter();
    path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
        && result.ident == "Result"
        && arguments.next().is_some_and(
            |argument| matches!(argument, GenericArgument::Type(ty) if is_plain_type(ty, ok)),
        )
        && arguments.next().is_some_and(
            |argument| matches!(argument, GenericArgument::Type(ty) if is_plain_type(ty, error)),
        )
        && arguments.next().is_none()
}

fn decode_message_has_documented_signature(source: &str) -> bool {
    let syntax = syn::parse_file(source).expect("message.rs must remain valid Rust");
    let mut functions = syntax.items.iter().filter_map(|item| match item {
        Item::Fn(function)
            if function.sig.ident == "decode_message" && is_public(&function.vis) =>
        {
            Some(function)
        }
        _ => None,
    });
    let Some(function) = functions.next() else {
        return false;
    };
    let mut inputs = function.sig.inputs.iter();
    let first_is_bytes = inputs.next().is_some_and(|argument| {
        matches!(
            argument,
            FnArg::Typed(argument)
                if matches!(argument.ty.as_ref(), Type::Reference(reference)
                    if reference.mutability.is_some() && is_plain_type(&reference.elem, "Bytes"))
        )
    });
    let second_is_u16 = inputs.next().is_some_and(
        |argument| matches!(argument, FnArg::Typed(argument) if is_plain_type(&argument.ty, "u16")),
    );
    let shadows_wire_type = function.sig.generics.params.iter().any(|parameter| {
        matches!(
            parameter,
            GenericParam::Type(parameter)
                if parameter.ident == "Bytes"
                    || parameter.ident == "Message"
                    || parameter.ident == "DecodeError"
        )
    });
    functions.next().is_none()
        && first_is_bytes
        && second_is_u16
        && inputs.next().is_none()
        && !shadows_wire_type
        && return_type_is_result(&function.sig.output, "Message", "DecodeError")
}

#[derive(Debug)]
enum UseEntry {
    Named { source: Vec<String>, local: String },
    Glob { source: Vec<String> },
}

fn flatten_use_tree(tree: &UseTree, prefix: &mut Vec<String>, entries: &mut Vec<UseEntry>) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use_tree(path.tree.as_ref(), prefix, entries);
            prefix.pop();
        }
        UseTree::Name(name) => {
            let mut source = prefix.clone();
            source.push(name.ident.to_string());
            entries.push(UseEntry::Named {
                source,
                local: name.ident.to_string(),
            });
        }
        UseTree::Rename(rename) => {
            let mut source = prefix.clone();
            source.push(rename.ident.to_string());
            entries.push(UseEntry::Named {
                source,
                local: rename.rename.to_string(),
            });
        }
        UseTree::Glob(_) => entries.push(UseEntry::Glob {
            source: prefix.clone(),
        }),
        UseTree::Group(group) => {
            for item in &group.items {
                flatten_use_tree(item, prefix, entries);
            }
        }
    }
}

fn use_entries(tree: &UseTree) -> Vec<UseEntry> {
    let mut entries = Vec::new();
    flatten_use_tree(tree, &mut Vec::new(), &mut entries);
    entries
}

fn message_imports_bytes_type(source: &str) -> bool {
    syn::parse_file(source)
        .expect("message.rs must remain valid Rust")
        .items
        .iter()
        .any(|item| {
            matches!(item, Item::Use(item_use) if use_entries(&item_use.tree).iter().any(|entry| {
                matches!(entry, UseEntry::Named { source, local }
                    if source == &["bytes", "Bytes"] && local == "Bytes")
            }))
        })
}

fn lib_has_no_root_bytes_reexport(source: &str) -> bool {
    syn::parse_file(source)
        .expect("lib.rs must remain valid Rust")
        .items
        .iter()
        .filter(|item| match item {
            Item::Use(item) => is_public(&item.vis),
            Item::ExternCrate(item) => is_public(&item.vis),
            Item::Type(item) => is_public(&item.vis),
            _ => false,
        })
        .all(|item| match item {
            Item::Use(item) => use_entries(&item.tree).iter().all(|entry| match entry {
                UseEntry::Named { source, .. } | UseEntry::Glob { source } => {
                    !source.first().is_some_and(|segment| segment == "bytes")
                }
            }),
            Item::ExternCrate(item) => item.ident != "bytes",
            Item::Type(item) => !matches!(item.ty.as_ref(), Type::Path(path)
                if path.qself.is_none()
                    && path.path.segments.first().is_some_and(|segment| segment.ident == "bytes")),
            _ => true,
        })
}

fn has_exact_feature_gate(attributes: &[Attribute], feature: &str) -> bool {
    let mut cfgs = attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg"));
    let Some(attribute) = cfgs.next() else {
        return false;
    };
    let Meta::List(list) = &attribute.meta else {
        return false;
    };
    cfgs.next().is_none()
        && !attributes
            .iter()
            .any(|attribute| attribute.path().is_ident("cfg_attr"))
        && compact_whitespace(&list.tokens.to_string()) == format!("feature = \"{feature}\"")
}

fn item_has_public_name(item: &Item, name: &str) -> bool {
    match item {
        Item::Enum(item) => is_public(&item.vis) && item.ident == name,
        Item::Struct(item) => is_public(&item.vis) && item.ident == name,
        Item::Type(item) => is_public(&item.vis) && item.ident == name,
        Item::Union(item) => is_public(&item.vis) && item.ident == name,
        Item::Trait(item) => is_public(&item.vis) && item.ident == name,
        Item::TraitAlias(item) => is_public(&item.vis) && item.ident == name,
        Item::Fn(item) => is_public(&item.vis) && item.sig.ident == name,
        Item::Const(item) => is_public(&item.vis) && item.ident == name,
        Item::Static(item) => is_public(&item.vis) && item.ident == name,
        Item::Mod(item) => is_public(&item.vis) && item.ident == name,
        Item::ExternCrate(item) => {
            is_public(&item.vis)
                && (item.ident == name
                    || item
                        .rename
                        .as_ref()
                        .is_some_and(|(_, rename)| rename == name))
        }
        _ => false,
    }
}

fn lib_has_exact_codec_gate(source: &str) -> bool {
    let syntax = syn::parse_file(source).expect("lib.rs must remain valid Rust");
    let modules = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) if is_public(&module.vis) && module.ident == "tokio_codec" => {
                Some(module)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if modules.len() != 1 || !has_exact_feature_gate(&modules[0].attrs, "tokio-codec") {
        return false;
    }

    let mut bindings = 0;
    let mut canonical_binding = false;
    for item in &syntax.items {
        if let Item::Use(item_use) = item
            && is_public(&item_use.vis)
        {
            for entry in use_entries(&item_use.tree) {
                match entry {
                    UseEntry::Named { source, local } if local == "BgpCodecError" => {
                        bindings += 1;
                        canonical_binding |= source == ["tokio_codec", "BgpCodecError"]
                            && has_exact_feature_gate(&item_use.attrs, "tokio-codec");
                    }
                    UseEntry::Glob { .. } => return false,
                    UseEntry::Named { .. } => {}
                }
            }
        } else if item_has_public_name(item, "BgpCodecError") {
            bindings += 1;
        }
    }
    bindings == 1 && canonical_binding
}

fn source_enum_is_public_and_non_exhaustive(source: &str, name: &str) -> bool {
    syn::parse_file(source)
        .expect("error source must remain valid Rust")
        .items
        .iter()
        .any(|item| {
            matches!(item, Item::Enum(item)
            if is_public(&item.vis)
                && item.ident == name
                && item.attrs.iter().any(|attribute| attribute.path().is_ident("non_exhaustive")))
        })
}

#[test]
fn usage_matches_the_published_wire_contract() {
    let usage = section(README, "## Usage");
    assert!(usage.contains(&expected_dependency_block(env!("CARGO_PKG_VERSION"))));
    assert!(usage.contains("`decode_message` accepts `&mut bytes::Bytes`"));
    assert!(usage.contains("the crate root does not expose a stable\n`Bytes` re-export"));
    assert!(decode_message_has_documented_signature(MESSAGE_SOURCE));
    assert!(message_imports_bytes_type(MESSAGE_SOURCE));
    assert!(lib_has_no_root_bytes_reexport(LIB_SOURCE));
}

#[test]
fn enum_guidance_matches_the_five_known_public_errors() {
    let exhaustiveness = section(README, "## Enum exhaustiveness");
    assert!(has_documented_error_roster(exhaustiveness));
    assert!(exhaustiveness.contains("must include\na wildcard arm"));
    assert!(exhaustiveness.contains("_ => {}"));
    for (source, name) in [
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
    ] {
        assert!(source_enum_is_public_and_non_exhaustive(source, name));
    }
    assert!(lib_has_exact_codec_gate(LIB_SOURCE));
}

#[test]
fn helpers_reject_contract_mutations() {
    for shadowed in ["Bytes", "Message", "DecodeError"] {
        let mutation = MESSAGE_SOURCE.replacen(
            "pub fn decode_message(",
            &format!("pub fn decode_message<{shadowed}>("),
            1,
        );
        assert!(!decode_message_has_documented_signature(&mutation));
    }
    let extra_codec_cfg = r#"
        #[cfg(feature = "tokio-codec")]
        #[cfg(unix)]
        pub mod tokio_codec {}
        #[cfg(feature = "tokio-codec")]
        pub use tokio_codec::BgpCodecError;
    "#;
    assert!(!lib_has_exact_codec_gate(extra_codec_cfg));
}
