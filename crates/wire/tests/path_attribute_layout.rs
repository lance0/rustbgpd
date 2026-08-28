use std::mem::size_of;
use std::net::Ipv4Addr;

use rustbgpd_wire::{
    Aggregator, AsPath, ExtendedCommunity, LargeCommunity, MpReachNlri, MpUnreachNlri, Origin,
    PathAttribute, PmsiTunnel, RawAttribute,
};

// Measurement-only mirror of the complete public enum. It intentionally has
// no constructors or conversions: its sole purpose is to expose the private
// boxed-candidate layout without changing rustbgpd-wire's public API.
#[allow(
    dead_code,
    reason = "all mirror variants must participate in the compiler's enum layout"
)]
enum BoxedMpPathAttributeMirror {
    Origin(Origin),
    AsPath(AsPath),
    Aggregator(Aggregator),
    AtomicAggregate,
    NextHop(Ipv4Addr),
    LocalPref(u32),
    Med(u32),
    Communities(Vec<u32>),
    CommunitiesPartial(Vec<u32>),
    ExtendedCommunities(Vec<ExtendedCommunity>),
    ExtendedCommunitiesPartial(Vec<ExtendedCommunity>),
    LargeCommunities(Vec<LargeCommunity>),
    LargeCommunitiesPartial(Vec<LargeCommunity>),
    OriginatorId(Ipv4Addr),
    ClusterList(Vec<Ipv4Addr>),
    MpReachNlri(Box<MpReachNlri>),
    MpUnreachNlri(Box<MpUnreachNlri>),
    PmsiTunnel(PmsiTunnel),
    PmsiTunnelPartial(PmsiTunnel),
    OnlyToCustomer(u32),
    OnlyToCustomerPartial(u32),
    Unknown(RawAttribute),
}

#[test]
fn reports_current_and_boxed_mp_path_attribute_layouts() {
    let candidate_payloads = [
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
    let largest_payload_size = candidate_payloads
        .iter()
        .map(|(_, size)| *size)
        .max()
        .expect("the complete mirror has payload variants");
    let largest_payloads: Vec<&str> = candidate_payloads
        .iter()
        .filter_map(|(name, size)| (*size == largest_payload_size).then_some(*name))
        .collect();

    eprintln!(
        "PathAttribute={} MpReachNlri={} MpUnreachNlri={} boxed_candidate={} largest_payload_bytes={} largest_payloads={}",
        size_of::<PathAttribute>(),
        size_of::<MpReachNlri>(),
        size_of::<MpUnreachNlri>(),
        size_of::<BoxedMpPathAttributeMirror>(),
        largest_payload_size,
        largest_payloads.join(","),
    );

    assert_eq!(size_of::<Box<MpReachNlri>>(), size_of::<usize>());
    assert_eq!(size_of::<Box<MpUnreachNlri>>(), size_of::<usize>());
    assert!(
        size_of::<BoxedMpPathAttributeMirror>() <= size_of::<PathAttribute>(),
        "boxing both MP payloads must not enlarge the complete enum mirror"
    );
    assert!(
        !largest_payloads.contains(&"MpReachNlri") && !largest_payloads.contains(&"MpUnreachNlri"),
        "neither boxed MP payload may remain the candidate's largest payload"
    );
    assert!(
        largest_payloads.contains(&"Unknown"),
        "RawAttribute must remain among the boxed candidate's largest payloads"
    );
}
