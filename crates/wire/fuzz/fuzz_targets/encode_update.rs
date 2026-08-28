#![no_main]
//! Construct canonical IPv4 UPDATEs and prove their complete encoder path.
//!
//! This target deliberately excludes inputs with specified normalization or
//! projection behavior: AS_SET, MP attributes, repeated attribute types,
//! duplicate community values, and opaque attributes. Those inputs cannot
//! support strict constructor-value equality even when their wire behavior is
//! correct. Decoder-focused targets cover their receive-side byte space.

use bytes::Bytes;
use libfuzzer_sys::arbitrary::{self, Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::attribute::{
    Aggregator, AsPath, AsPathSegment, ExtendedCommunity, LargeCommunity, Origin, PathAttribute,
};
use rustbgpd_wire::nlri::{Ipv4NlriEntry, Ipv4Prefix};
use rustbgpd_wire::{Ipv4UnicastMode, MAX_MESSAGE_LEN, Message, UpdateMessage, decode_message};
use std::net::Ipv4Addr;

const MAX_ITEMS: usize = 8;

#[derive(Arbitrary)]
struct PrefixRecipe {
    address: [u8; 4],
    length: u8,
}

#[derive(Arbitrary)]
struct LargeCommunityRecipe {
    global_admin: u32,
    local_data1: u32,
    local_data2: u32,
}

#[derive(Arbitrary)]
struct UpdateRecipe {
    origin: u8,
    as_path_len: u8,
    asns: [u32; MAX_ITEMS],
    next_hop: [u8; 4],
    announced_len: u8,
    announced: [PrefixRecipe; MAX_ITEMS],
    withdrawn_len: u8,
    withdrawn: [PrefixRecipe; MAX_ITEMS],
    present: u16,
    partial: u16,
    local_pref: u32,
    med: u32,
    communities_len: u8,
    communities: [u32; MAX_ITEMS],
    extended_communities_len: u8,
    extended_communities: [u64; MAX_ITEMS],
    large_communities_len: u8,
    large_communities: [LargeCommunityRecipe; MAX_ITEMS],
    originator_id: [u8; 4],
    cluster_list_len: u8,
    cluster_list: [[u8; 4]; MAX_ITEMS],
    aggregator_asn: u32,
    aggregator_id: [u8; 4],
    otc_asn: u32,
}

fn unique_take<T: Copy + Eq>(values: &[T], count: u8, require_one: bool) -> Vec<T> {
    let count = if require_one {
        usize::from(count) % values.len() + 1
    } else {
        usize::from(count) % (values.len() + 1)
    };
    let mut selected = Vec::with_capacity(count);
    for value in values.iter().copied().take(count) {
        if !selected.contains(&value) {
            selected.push(value);
        }
    }
    selected
}

fn prefixes(recipes: &[PrefixRecipe], count: u8, require_one: bool) -> Vec<Ipv4NlriEntry> {
    let count = if require_one {
        usize::from(count) % recipes.len() + 1
    } else {
        usize::from(count) % (recipes.len() + 1)
    };
    let mut entries = Vec::with_capacity(count);
    for recipe in recipes.iter().take(count) {
        let entry = Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::from(recipe.address), recipe.length),
        };
        if !entries.contains(&entry) {
            entries.push(entry);
        }
    }
    entries
}

fn attributes(recipe: &UpdateRecipe) -> Vec<PathAttribute> {
    let origin = match recipe.origin % 3 {
        0 => Origin::Igp,
        1 => Origin::Egp,
        _ => Origin::Incomplete,
    };
    let asn_count = usize::from(recipe.as_path_len) % (recipe.asns.len() + 1);
    let asns: Vec<_> = recipe.asns.iter().copied().take(asn_count).collect();
    let as_path = if asns.is_empty() {
        AsPath { segments: vec![] }
    } else {
        AsPath {
            segments: vec![AsPathSegment::AsSequence(asns)],
        }
    };
    let mut attrs = vec![
        PathAttribute::Origin(origin),
        PathAttribute::AsPath(as_path),
        PathAttribute::NextHop(Ipv4Addr::from(recipe.next_hop)),
    ];

    if recipe.present & (1 << 0) != 0 {
        attrs.push(PathAttribute::LocalPref(recipe.local_pref));
    }
    if recipe.present & (1 << 1) != 0 {
        attrs.push(PathAttribute::Med(recipe.med));
    }
    if recipe.present & (1 << 2) != 0 {
        let values = unique_take(&recipe.communities, recipe.communities_len, true);
        attrs.push(if recipe.partial & (1 << 2) != 0 {
            PathAttribute::CommunitiesPartial(values)
        } else {
            PathAttribute::Communities(values)
        });
    }
    if recipe.present & (1 << 3) != 0 {
        let values = unique_take(
            &recipe.extended_communities,
            recipe.extended_communities_len,
            true,
        )
        .into_iter()
        .map(ExtendedCommunity::new)
        .collect();
        attrs.push(if recipe.partial & (1 << 3) != 0 {
            PathAttribute::ExtendedCommunitiesPartial(values)
        } else {
            PathAttribute::ExtendedCommunities(values)
        });
    }
    if recipe.present & (1 << 4) != 0 {
        let candidates: Vec<_> = recipe
            .large_communities
            .iter()
            .map(|value| {
                LargeCommunity::new(value.global_admin, value.local_data1, value.local_data2)
            })
            .collect();
        let values = unique_take(&candidates, recipe.large_communities_len, true);
        attrs.push(if recipe.partial & (1 << 4) != 0 {
            PathAttribute::LargeCommunitiesPartial(values)
        } else {
            PathAttribute::LargeCommunities(values)
        });
    }
    if recipe.present & (1 << 5) != 0 {
        attrs.push(PathAttribute::OriginatorId(Ipv4Addr::from(
            recipe.originator_id,
        )));
    }
    if recipe.present & (1 << 6) != 0 {
        let values = unique_take(&recipe.cluster_list, recipe.cluster_list_len, true)
            .into_iter()
            .map(Ipv4Addr::from)
            .collect();
        attrs.push(PathAttribute::ClusterList(values));
    }
    if recipe.present & (1 << 7) != 0 {
        attrs.push(PathAttribute::AtomicAggregate);
    }
    if recipe.present & (1 << 8) != 0 {
        attrs.push(PathAttribute::Aggregator(Aggregator {
            asn: recipe.aggregator_asn,
            router_id: Ipv4Addr::from(recipe.aggregator_id),
            partial: recipe.partial & (1 << 8) != 0,
        }));
    }
    if recipe.present & (1 << 9) != 0 {
        attrs.push(if recipe.partial & (1 << 9) != 0 {
            PathAttribute::OnlyToCustomerPartial(recipe.otc_asn)
        } else {
            PathAttribute::OnlyToCustomer(recipe.otc_asn)
        });
    }
    attrs
}

fuzz_target!(|data: &[u8]| {
    // Keep direct reproductions and every hosted builder on the same reviewed
    // constructor-input boundary, independently of runner configuration.
    if data.len() > 4_096 {
        return;
    }
    let mut input = Unstructured::new(data);
    let Ok(recipe) = UpdateRecipe::arbitrary(&mut input) else {
        return;
    };

    let announced = prefixes(&recipe.announced, recipe.announced_len, true);
    let withdrawn = prefixes(&recipe.withdrawn, recipe.withdrawn_len, false);
    let attrs = attributes(&recipe);
    let update = UpdateMessage::try_build(
        &announced,
        &withdrawn,
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    )
    .expect("canonical structured UPDATE must encode");

    let mut encoded = Vec::with_capacity(update.encoded_len());
    update
        .encode(&mut encoded)
        .expect("bounded structured UPDATE must fit the standard message limit");
    assert_eq!(encoded.len(), update.encoded_len());

    let mut full_message = Bytes::copy_from_slice(&encoded);
    let decoded = decode_message(&mut full_message, MAX_MESSAGE_LEN)
        .expect("encoder output must decode as a complete message");
    assert!(
        full_message.is_empty(),
        "full decode must consume every byte"
    );
    let Message::Update(decoded_update) = decoded else {
        panic!("UPDATE encoder produced a different BGP message type");
    };
    assert_eq!(
        decoded_update, update,
        "full-message framing must be stable"
    );

    let parsed = decoded_update
        .parse_revised(true, true, false, &[])
        .expect("canonical structured UPDATE must parse");
    assert!(
        parsed.malformed.is_empty(),
        "encoder emitted malformed attrs"
    );
    assert_eq!(parsed.update.announced, announced);
    assert_eq!(parsed.update.withdrawn, withdrawn);
    assert_eq!(parsed.update.attributes, attrs);
    assert_eq!(parsed.update.bgpls_nlri_discarded, 0);

    let rebuilt = UpdateMessage::try_build(
        &parsed.update.announced,
        &parsed.update.withdrawn,
        &parsed.update.attributes,
        true,
        false,
        Ipv4UnicastMode::Body,
    )
    .expect("decoded canonical UPDATE must re-encode");
    let mut reencoded = Vec::with_capacity(rebuilt.encoded_len());
    rebuilt.encode(&mut reencoded).expect("re-encode must fit");
    assert_eq!(reencoded, encoded, "canonical re-encoding must be stable");
});
