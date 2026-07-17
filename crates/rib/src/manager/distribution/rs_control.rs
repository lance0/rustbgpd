//! RFC 7947 §2.3.2 / RFC 8195 route-server control communities.
//!
//! A route-server client steers per-target-peer distribution by tagging
//! its announcements with control communities keyed on the TARGET
//! peer's ASN (the route server cannot know a member's selective
//! peering policy any other way — RFC 7947 is explicit that only the
//! RS performs outbound filtering for its clients). Enforcement is a
//! per-target export-staging decision, gated by the per-peer
//! `rs_control_communities` knob (default on for route-server-client
//! sessions) which arrives as the session's RS-side local ASN via
//! [`crate::update::RibUpdate::SetPeerRsControl`].
//!
//! The recognized matrix, with `RS` the route server's ASN and `PEER`
//! the target peer's ASN (standard forms exist only when both ASNs fit
//! 16 bits; the large forms are the RFC 8195 idiom and work for 4-byte
//! ASNs — extended-community control forms are deliberately not
//! implemented, per draft-ietf-grow-ixp-ext-comms guidance):
//!
//! | Action                     | Standard    | Large           |
//! |----------------------------|-------------|-----------------|
//! | Do not announce to `PEER`  | `0:PEER`    | `RS:0:PEER`     |
//! | Announce to `PEER` (override of announce-to-none) | `RS:PEER` | `RS:1:PEER` |
//! | Do not announce to any peer| `0:RS`      | `RS:0:0`        |
//! | Prepend client ASN 1x toward `PEER` | —  | `RS:101:PEER`   |
//! | Prepend client ASN 2x toward `PEER` | —  | `RS:102:PEER`   |
//! | Prepend client ASN 3x toward `PEER` | —  | `RS:103:PEER`   |
//! | Prepend toward every peer  | —           | `RS:10x:0`      |
//!
//! Evaluation order (the deny-specific ladder every major IXP
//! documents): a target-specific "do not announce" always suppresses;
//! otherwise "announce to none" suppresses unless a target-specific
//! "announce to" overrides it; otherwise the route is announced.
//! Prepending applies only to announced routes and prepends the
//! path's leftmost ASN (the announcing client — the transparent RS
//! never inserts its own ASN), with the largest matching count
//! winning.
//!
//! Control communities are acted on by the RS and scrubbed from the
//! outbound announcement toward enabled targets: standard communities
//! whose administrator field is `0` or `RS` (the RFC 1997 well-known
//! `0xFFFF____` space is excluded), and large communities with global
//! administrator `RS` and a control function (`0`, `1`, `101`–`103`).
//! Informational large communities under the RS ASN with other
//! function values pass through untouched. Sessions with the knob off
//! keep full transparency: nothing is interpreted or scrubbed.

use std::sync::Arc;

use rustbgpd_policy::RouteModifications;
use rustbgpd_wire::{AsPath, AsPathSegment, LargeCommunity};

/// Large-community function values for the prepend actions, paired
/// with their prepend counts.
const PREPEND_FUNCTIONS: [(u32, u8); 3] = [(101, 1), (102, 2), (103, 3)];

/// Standard community `admin:value`, only representable when both
/// halves fit 16 bits.
fn std_community(admin: u32, value: u32) -> Option<u32> {
    (admin <= 0xFFFF && value <= 0xFFFF).then_some((admin << 16) | value)
}

/// RFC 7947 §2.3.2 per-target announce decision on the SOURCE route
/// (pre-policy, like the RFC 1997 gates): `true` when the control
/// communities forbid announcing this route to `peer_asn`.
pub(super) fn rs_control_export_suppressed(
    communities: &[u32],
    large_communities: &[LargeCommunity],
    rs_asn: u32,
    peer_asn: u32,
) -> bool {
    let has_std =
        |admin, value| std_community(admin, value).is_some_and(|c| communities.contains(&c));
    let has_large = |data1: u32, data2: u32| {
        large_communities.iter().any(|lc| {
            lc.global_admin == rs_asn && lc.local_data1 == data1 && lc.local_data2 == data2
        })
    };
    // Target-specific deny always wins.
    if has_std(0, peer_asn) || has_large(0, peer_asn) {
        return true;
    }
    // Announce-to-none, overridable by a target-specific announce.
    if has_std(0, rs_asn) || has_large(0, 0) {
        return !(has_std(rs_asn, peer_asn) || has_large(1, peer_asn));
    }
    false
}

/// Prepend count toward `peer_asn`: the largest matching
/// `RS:101|102|103:PEER` (target-specific) or `RS:10x:0` (every
/// target) large community, `0` when none match.
pub(super) fn rs_control_prepend_count(
    large_communities: &[LargeCommunity],
    rs_asn: u32,
    peer_asn: u32,
) -> u8 {
    let mut count = 0u8;
    for lc in large_communities {
        if lc.global_admin != rs_asn || (lc.local_data2 != peer_asn && lc.local_data2 != 0) {
            continue;
        }
        if let Some(&(_, n)) = PREPEND_FUNCTIONS
            .iter()
            .find(|&&(f, _)| f == lc.local_data1)
        {
            count = count.max(n);
        }
    }
    count
}

/// A standard community in the control space: administered by `0` or
/// `RS`, excluding the RFC 1997 well-known `0xFFFF____` space.
fn is_std_control(community: u32, rs_asn: u32) -> bool {
    let admin = community >> 16;
    admin != 0xFFFF && (admin == 0 || admin == rs_asn)
}

/// A large community in the control space: global administrator `RS`
/// with a control function (`0`, `1`, `101`–`103`).
fn is_large_control(lc: &LargeCommunity, rs_asn: u32) -> bool {
    lc.global_admin == rs_asn
        && (lc.local_data1 <= 1 || PREPEND_FUNCTIONS.iter().any(|&(f, _)| f == lc.local_data1))
}

/// Route-granular classification for the emit-time filter (LAN-474):
/// does this route carry ANY control-form community for `rs_asn`? The
/// domain is exactly the scrub domain — every suppression, override,
/// and prepend form is also a scrub form — so untagged routes (the
/// overwhelming majority) provably need no per-target divergence and
/// keep riding the shared update-group emission.
pub(in crate::manager) fn rs_control_route_tagged(
    communities: &[u32],
    large_communities: &[LargeCommunity],
    rs_asn: u32,
) -> bool {
    communities.iter().any(|&c| is_std_control(c, rs_asn))
        || large_communities
            .iter()
            .any(|lc| is_large_control(lc, rs_asn))
}

/// Per-target suppression at the group emit seam: `rs` is
/// `(rs_asn, target_peer_asn)` for an enabled session, `None` when the
/// knob is off (never suppressed).
pub(in crate::manager) fn rs_control_route_suppressed(
    route: &crate::route::Route,
    rs: Option<(u32, u32)>,
) -> bool {
    rs.is_some_and(|(rs_asn, peer_asn)| {
        rs_control_export_suppressed(
            route.communities(),
            route.large_communities(),
            rs_asn,
            peer_asn,
        )
    })
}

/// Per-target egress rewrite (prepend + scrub) at the group emit seam,
/// for a route already cleared by [`rs_control_route_suppressed`].
/// No-op (and allocation-free) for untagged routes or a disabled
/// session.
pub(in crate::manager) fn rs_control_route_rewrite(
    route: &mut crate::route::Route,
    rs: Option<(u32, u32)>,
) {
    if let Some((rs_asn, peer_asn)) = rs {
        let prepend = rs_control_prepend_count(route.large_communities(), rs_asn, peer_asn);
        apply_rs_control_egress(route, rs_asn, prepend);
    }
}

/// The control communities present on an outbound attribute set that
/// must be scrubbed before the wire: standard communities administered
/// by `0` or `RS` (excluding the RFC 1997 well-known `0xFFFF____`
/// space), and large communities `RS:{0,1,101,102,103}:*`.
fn scrub_lists(
    communities: &[u32],
    large_communities: &[LargeCommunity],
    rs_asn: u32,
) -> (Vec<u32>, Vec<LargeCommunity>) {
    let std_remove = communities
        .iter()
        .copied()
        .filter(|&c| is_std_control(c, rs_asn))
        .collect();
    let large_remove = large_communities
        .iter()
        .filter(|lc| is_large_control(lc, rs_asn))
        .copied()
        .collect();
    (std_remove, large_remove)
}

/// Leftmost ASN of the path — the announcing client of a transparent
/// route server. `None` for an empty path or a path led by an
/// `AS_SET` (nonstandard; prepending is skipped rather than guessed).
fn leftmost_asn(as_path: Option<&AsPath>) -> Option<u32> {
    match as_path?.segments.first()? {
        AsPathSegment::AsSequence(asns) => asns.first().copied(),
        AsPathSegment::AsSet(_) => None,
    }
}

/// Apply the outbound control-community actions to a staged per-peer
/// route clone: prepend the announcing client's ASN `prepend` times
/// and scrub the control communities. Reuses the policy crate's
/// `apply_modifications` (attribute-drop on emptied community lists,
/// tested prepend segment handling). `Arc::make_mut` keeps shared
/// attribute `Arc`s (pass-scoped `ExportMemo`, group-table shells)
/// copy-on-write — only TAGGED routes pay a per-target attribute
/// clone; untagged routes never reach this rewrite on the grouped
/// emit-filter path (LAN-474).
pub(super) fn apply_rs_control_egress(route: &mut crate::route::Route, rs_asn: u32, prepend: u8) {
    let (communities_remove, large_communities_remove) =
        scrub_lists(route.communities(), route.large_communities(), rs_asn);
    let as_path_prepend = (prepend > 0)
        .then(|| leftmost_asn(route.as_path()))
        .flatten()
        .map(|asn| (asn, prepend));
    if communities_remove.is_empty()
        && large_communities_remove.is_empty()
        && as_path_prepend.is_none()
    {
        return;
    }
    let mods = RouteModifications {
        communities_remove,
        large_communities_remove,
        as_path_prepend,
        ..RouteModifications::default()
    };
    rustbgpd_policy::apply_modifications(Arc::make_mut(&mut route.attributes), &mods);
}

#[cfg(test)]
mod tests {
    use super::*;

    const RS: u32 = 65000;
    const PEER_A: u32 = 65001;
    const PEER_B: u32 = 65002;

    fn large(global_admin: u32, data1: u32, data2: u32) -> LargeCommunity {
        LargeCommunity {
            global_admin,
            local_data1: data1,
            local_data2: data2,
        }
    }

    fn std(admin: u32, value: u32) -> u32 {
        (admin << 16) | value
    }

    #[test]
    fn untagged_route_announced_to_everyone() {
        assert!(!rs_control_export_suppressed(&[], &[], RS, PEER_A));
        assert!(!rs_control_export_suppressed(
            &[std(64999, 7)],
            &[large(64999, 0, PEER_A)], // wrong global admin — not ours
            RS,
            PEER_A
        ));
    }

    #[test]
    fn do_not_announce_to_target_std_and_large() {
        // 0:PEER suppresses toward PEER only.
        assert!(rs_control_export_suppressed(
            &[std(0, PEER_A)],
            &[],
            RS,
            PEER_A
        ));
        assert!(!rs_control_export_suppressed(
            &[std(0, PEER_A)],
            &[],
            RS,
            PEER_B
        ));
        // RS:0:PEER — the 4-byte-safe form.
        let lc = [large(RS, 0, PEER_A)];
        assert!(rs_control_export_suppressed(&[], &lc, RS, PEER_A));
        assert!(!rs_control_export_suppressed(&[], &lc, RS, PEER_B));
    }

    #[test]
    fn announce_to_none_std_and_large() {
        assert!(rs_control_export_suppressed(&[std(0, RS)], &[], RS, PEER_A));
        assert!(rs_control_export_suppressed(&[std(0, RS)], &[], RS, PEER_B));
        let lc = [large(RS, 0, 0)];
        assert!(rs_control_export_suppressed(&[], &lc, RS, PEER_A));
        assert!(rs_control_export_suppressed(&[], &lc, RS, PEER_B));
    }

    #[test]
    fn announce_only_to_target_overrides_announce_to_none() {
        // std form: 0:RS + RS:PEER_A ⇒ only PEER_A.
        let cs = [std(0, RS), std(RS, PEER_A)];
        assert!(!rs_control_export_suppressed(&cs, &[], RS, PEER_A));
        assert!(rs_control_export_suppressed(&cs, &[], RS, PEER_B));
        // large form: RS:0:0 + RS:1:PEER_A ⇒ only PEER_A.
        let lc = [large(RS, 0, 0), large(RS, 1, PEER_A)];
        assert!(!rs_control_export_suppressed(&[], &lc, RS, PEER_A));
        assert!(rs_control_export_suppressed(&[], &lc, RS, PEER_B));
        // Mixed encodings compose: std announce-to-none + large override.
        let cs = [std(0, RS)];
        let lc = [large(RS, 1, PEER_A)];
        assert!(!rs_control_export_suppressed(&cs, &lc, RS, PEER_A));
        assert!(rs_control_export_suppressed(&cs, &lc, RS, PEER_B));
    }

    #[test]
    fn target_specific_deny_outranks_announce_override() {
        // RS:1:PEER cannot resurrect a route that also carries the
        // target-specific deny — deny-specific always wins.
        let lc = [large(RS, 0, PEER_A), large(RS, 1, PEER_A)];
        assert!(rs_control_export_suppressed(&[], &lc, RS, PEER_A));
    }

    #[test]
    fn four_byte_asns_have_no_std_form() {
        // A 4-byte RS ASN: 0:RS cannot be encoded, so a random standard
        // community must not be misread; the large forms still work.
        let big_rs = 4_200_000_000;
        assert!(!rs_control_export_suppressed(
            &[std(0, 1234)],
            &[],
            big_rs,
            PEER_A
        ));
        assert!(rs_control_export_suppressed(
            &[],
            &[large(big_rs, 0, PEER_A)],
            big_rs,
            PEER_A
        ));
    }

    #[test]
    fn prepend_counts_target_specific_wildcard_and_max_wins() {
        let lc = [large(RS, 102, PEER_A)];
        assert_eq!(rs_control_prepend_count(&lc, RS, PEER_A), 2);
        assert_eq!(rs_control_prepend_count(&lc, RS, PEER_B), 0);
        // Wildcard target 0 hits every peer.
        let lc = [large(RS, 101, 0)];
        assert_eq!(rs_control_prepend_count(&lc, RS, PEER_A), 1);
        assert_eq!(rs_control_prepend_count(&lc, RS, PEER_B), 1);
        // Largest matching count wins.
        let lc = [large(RS, 101, 0), large(RS, 103, PEER_A)];
        assert_eq!(rs_control_prepend_count(&lc, RS, PEER_A), 3);
        assert_eq!(rs_control_prepend_count(&lc, RS, PEER_B), 1);
        // Wrong global admin never counts.
        let lc = [large(64999, 103, PEER_A)];
        assert_eq!(rs_control_prepend_count(&lc, RS, PEER_A), 0);
    }

    #[test]
    fn tagged_predicate_matches_exactly_the_scrub_domain() {
        // Untagged: no communities, foreign admins, well-known space,
        // informational large under the RS admin.
        assert!(!rs_control_route_tagged(&[], &[], RS));
        assert!(!rs_control_route_tagged(
            &[
                std(64999, 42),
                rustbgpd_wire::COMMUNITY_NO_EXPORT,
                rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN
            ],
            &[large(RS, 1000, 7), large(64999, 0, PEER_A)],
            RS
        ));
        // Tagged: each control form flips the predicate on its own.
        assert!(rs_control_route_tagged(&[std(0, PEER_A)], &[], RS));
        assert!(rs_control_route_tagged(&[std(RS, PEER_A)], &[], RS));
        assert!(rs_control_route_tagged(&[], &[large(RS, 0, PEER_A)], RS));
        assert!(rs_control_route_tagged(&[], &[large(RS, 1, PEER_A)], RS));
        assert!(rs_control_route_tagged(&[], &[large(RS, 102, 0)], RS));
    }

    #[test]
    fn scrub_matches_control_forms_only() {
        let communities = [
            std(0, PEER_A),                             // control: scrubbed
            std(RS, PEER_B),                            // control: scrubbed
            std(64999, 42),                             // foreign: kept
            rustbgpd_wire::COMMUNITY_NO_EXPORT,         // well-known: kept
            rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN, // well-known: kept
        ];
        let large_communities = [
            large(RS, 0, PEER_A),    // control: scrubbed
            large(RS, 1, PEER_B),    // control: scrubbed
            large(RS, 102, 0),       // control: scrubbed
            large(RS, 1000, 7),      // informational under RS admin: kept
            large(64999, 0, PEER_A), // foreign admin: kept
        ];
        let (std_remove, large_remove) = scrub_lists(&communities, &large_communities, RS);
        assert_eq!(std_remove, vec![std(0, PEER_A), std(RS, PEER_B)]);
        assert_eq!(
            large_remove,
            vec![
                large(RS, 0, PEER_A),
                large(RS, 1, PEER_B),
                large(RS, 102, 0)
            ]
        );
    }

    #[test]
    fn leftmost_asn_shapes() {
        assert_eq!(leftmost_asn(None), None);
        let empty = AsPath { segments: vec![] };
        assert_eq!(leftmost_asn(Some(&empty)), None);
        let seq = AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![PEER_A, 64999])],
        };
        assert_eq!(leftmost_asn(Some(&seq)), Some(PEER_A));
        let set_led = AsPath {
            segments: vec![
                AsPathSegment::AsSet(vec![PEER_A]),
                AsPathSegment::AsSequence(vec![64999]),
            ],
        };
        assert_eq!(leftmost_asn(Some(&set_led)), None);
    }
}
