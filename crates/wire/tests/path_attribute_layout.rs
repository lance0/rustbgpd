use std::mem::size_of;
use std::net::Ipv4Addr;

use rustbgpd_wire::{
    Aggregator, AsPath, ExtendedCommunity, LargeCommunity, MpReachNlri, MpUnreachNlri, Origin,
    PathAttribute, PmsiTunnel, RawAttribute,
};

// Every stored attribute set pays `size_of::<PathAttribute>()` per slot, so
// the enum is only as small as its largest payload. The MP payloads are
// boxed for that reason; this test names the payload that now sets the size
// and fails if any variant grows the enum past it.
#[test]
fn path_attribute_is_sized_by_its_largest_unboxed_payload() {
    let payloads = [
        ("Origin", size_of::<Origin>()),
        ("AsPath", size_of::<AsPath>()),
        ("Aggregator", size_of::<Aggregator>()),
        ("AtomicAggregate", 0),
        ("NextHop", size_of::<Ipv4Addr>()),
        ("LocalPref", size_of::<u32>()),
        ("Med", size_of::<u32>()),
        ("Communities", size_of::<Vec<u32>>()),
        ("CommunitiesPartial", size_of::<Vec<u32>>()),
        ("ExtendedCommunities", size_of::<Vec<ExtendedCommunity>>()),
        (
            "ExtendedCommunitiesPartial",
            size_of::<Vec<ExtendedCommunity>>(),
        ),
        ("LargeCommunities", size_of::<Vec<LargeCommunity>>()),
        ("LargeCommunitiesPartial", size_of::<Vec<LargeCommunity>>()),
        ("OriginatorId", size_of::<Ipv4Addr>()),
        ("ClusterList", size_of::<Vec<Ipv4Addr>>()),
        ("MpReachNlri", size_of::<Box<MpReachNlri>>()),
        ("MpUnreachNlri", size_of::<Box<MpUnreachNlri>>()),
        ("PmsiTunnel", size_of::<PmsiTunnel>()),
        ("PmsiTunnelPartial", size_of::<PmsiTunnel>()),
        ("OnlyToCustomer", size_of::<u32>()),
        ("OnlyToCustomerPartial", size_of::<u32>()),
        ("Unknown", size_of::<RawAttribute>()),
    ];
    let largest_payload_size = payloads
        .iter()
        .map(|(_, size)| *size)
        .max()
        .expect("the enum has payload variants");
    let largest_payloads: Vec<&str> = payloads
        .iter()
        .filter_map(|(name, size)| (*size == largest_payload_size).then_some(*name))
        .collect();

    eprintln!(
        "PathAttribute={} MpReachNlri={} MpUnreachNlri={} largest_payload_bytes={} largest_payloads={}",
        size_of::<PathAttribute>(),
        size_of::<MpReachNlri>(),
        size_of::<MpUnreachNlri>(),
        largest_payload_size,
        largest_payloads.join(","),
    );

    assert!(
        !largest_payloads.contains(&"MpReachNlri") && !largest_payloads.contains(&"MpUnreachNlri"),
        "a boxed MP payload must not be the enum's largest payload"
    );
    assert!(
        largest_payloads.contains(&"Unknown"),
        "RawAttribute must remain among the largest payloads"
    );
    // One word covers the discriminant plus alignment padding. A larger enum
    // means some payload is being stored inline that the table above misses.
    assert!(
        size_of::<PathAttribute>() <= largest_payload_size + size_of::<usize>(),
        "PathAttribute ({} B) grew past its largest listed payload ({} B) plus a tag word",
        size_of::<PathAttribute>(),
        largest_payload_size,
    );
}
