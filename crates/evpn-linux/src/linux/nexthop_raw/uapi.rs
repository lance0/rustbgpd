//! UAPI constants and structures for the Linux nexthop netlink API.
//!
//! Sourced from `include/uapi/linux/nexthop.h` and
//! `include/uapi/linux/rtnetlink.h`. Field layouts are facts (not
//! copyrightable); the per-item rustdoc here is original prose,
//! not copied from kernel headers.
//!
//! ADR-0059 §3 pins the exact constants table this module exposes;
//! cross-reference if any value here changes.
//!
//! All `pub(crate)` — callers go through the higher-level
//! [`super::NexthopSocket`] surface, never the raw UAPI types.
#![allow(dead_code)] // Dump-tolerance constants are pinned even when not emitted.

/// Create or update a nexthop entry (`RTM_NEWNEXTHOP`).
pub(crate) const RTM_NEWNEXTHOP: u16 = 104;

/// Delete a nexthop entry (`RTM_DELNEXTHOP`).
pub(crate) const RTM_DELNEXTHOP: u16 = 105;

/// Dump existing nexthop entries (`RTM_GETNEXTHOP`). Used by the
/// ADR-0059 L2 FDB-NHG adoption/drift path and the ADR-0090 L3
/// all-active Type 5 adoption/drift path.
pub(crate) const RTM_GETNEXTHOP: u16 = 106;

/// `NHA_UNSPEC` — placeholder type 0, never emitted.
pub(crate) const NHA_UNSPEC: u16 = 0;

/// `NHA_ID` — `u32` carrying the nexthop ID. First attribute on
/// every message we emit.
pub(crate) const NHA_ID: u16 = 1;

/// `NHA_GROUP` — array of [`NexthopGrp`] entries naming the
/// per-VTEP nexthop IDs that form an ECMP group.
pub(crate) const NHA_GROUP: u16 = 2;

/// `NHA_OIF` — output interface index. Unused for FDB nexthops
/// (FDB anchors are L2 and key on a `(VTEP IP, VXLAN dev)` pair
/// resolved via the FDB row's `NDA_NH_ID` reference, not on an
/// output device on the nexthop itself).
pub(crate) const NHA_OIF: u16 = 4;

/// `NHA_GATEWAY` — IPv4 (4 bytes) or IPv6 (16 bytes) next-hop
/// address in network byte order inside the attribute payload.
pub(crate) const NHA_GATEWAY: u16 = 6;

/// `NHA_FDB` — zero-length flag marking the nexthop as an FDB
/// (L2) anchor rather than an L3 nexthop. Required for both
/// per-VTEP entries and groups consumed by `NDA_NH_ID` on bridge
/// FDB rows.
pub(crate) const NHA_FDB: u16 = 11;

/// `NHA_GROUP_TYPE` — `u16` discriminator for group flavor
/// (MPATH vs resilient). Kernel may include this on dump even when
/// we don't set it on add; the dump parser tolerates and ignores it.
pub(crate) const NHA_GROUP_TYPE: u16 = 3;

/// `NHA_OP_FLAGS` — bitmask added in newer kernels; emitted on
/// dump regardless of whether userspace set it. Parser tolerates.
pub(crate) const NHA_OP_FLAGS: u16 = 15;

/// `NEXTHOP_GRP_TYPE_MPATH` — kernel default; we omit
/// `NHA_GROUP_TYPE` entirely, which yields MPATH semantics.
pub(crate) const NEXTHOP_GRP_TYPE_MPATH: u16 = 0;

/// `nhmsg` — the fixed-size header that follows `nlmsghdr` on
/// every `RTM_*NEXTHOP` message.
///
/// The on-wire layout is `{ u8, u8, u8, u8, u32 }` = 8 bytes after
/// natural alignment of the trailing `u32`. The kernel header
/// declares it as five fields (`nh_family`, `nh_scope`,
/// `nh_protocol`, `resvd`, `nh_flags`); we mirror that exactly.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Nhmsg {
    /// `AF_INET` / `AF_INET6` for per-VTEP nexthops with a
    /// gateway; `AF_UNSPEC` for groups and deletes. iproute2's
    /// `ip nexthop add` sets this from the v4/v6 form of the
    /// gateway argument.
    pub nh_family: u8,
    /// Routing scope. iproute2 uses `RT_SCOPE_UNIVERSE` (0) for
    /// every FDB nexthop case we tested.
    pub nh_scope: u8,
    /// Routing protocol that installed the nexthop. iproute2
    /// uses `RTPROT_UNSPEC` (0); the kernel does not require
    /// `RTPROT_BGP` for FDB-NHG installs.
    pub nh_protocol: u8,
    /// Reserved; always zero on the wire.
    pub resvd: u8,
    /// Nexthop flags (`RTNH_F_*`). Zero for the FDB case.
    pub nh_flags: u32,
}

/// `nexthop_grp` — one member of a nexthop group, as carried
/// inside an `NHA_GROUP` attribute payload.
///
/// The on-wire layout is `{ u32, u8, u8, u16 }` = 8 bytes. The
/// `weight` byte is the kernel-visible weight (0 means weight 1
/// per `nexthop_grp_weight()` in `uapi/linux/nexthop.h`). The
/// `resvd1` and `resvd2` fields are spelled exactly as the UAPI
/// header does — do not rename `resvd1` to `weight_high`; the
/// kernel does not treat it as a weight high-byte.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NexthopGrp {
    /// Nexthop ID of one member in this group. Must reference an
    /// existing entry (the kernel `EINVAL`s on dangling members
    /// — ADR-0059 §5 invariant 1).
    pub id: u32,
    /// Member weight. 0 = "weight 1" per kernel semantics.
    pub weight: u8,
    /// Reserved.
    pub resvd1: u8,
    /// Reserved.
    pub resvd2: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn nhmsg_layout_matches_uapi() {
        // 4 bytes of u8 + u32 (4 bytes, naturally aligned) = 8.
        assert_eq!(size_of::<Nhmsg>(), 8);
    }

    #[test]
    fn nexthop_grp_layout_matches_uapi() {
        // u32 + u8 + u8 + u16 = 8 bytes, naturally aligned.
        assert_eq!(size_of::<NexthopGrp>(), 8);
    }

    #[test]
    fn constants_match_adr_0059_uapi_table() {
        // ADR-0059 §3 pins these values; if you change any, update
        // the ADR + this test together.
        assert_eq!(RTM_NEWNEXTHOP, 104);
        assert_eq!(RTM_DELNEXTHOP, 105);
        assert_eq!(RTM_GETNEXTHOP, 106);
        assert_eq!(NHA_UNSPEC, 0);
        assert_eq!(NHA_ID, 1);
        assert_eq!(NHA_GROUP, 2);
        assert_eq!(NHA_OIF, 4);
        assert_eq!(NHA_GATEWAY, 6);
        assert_eq!(NHA_FDB, 11);
        // ADR-0059 dump-path tolerance — kernel may emit
        // these on `RTM_GETNEXTHOP` even when we don't set them on
        // add, so the parser ignores them by id. Drift here breaks
        // the dump filter silently, so pin the values.
        assert_eq!(NHA_GROUP_TYPE, 3);
        assert_eq!(NHA_OP_FLAGS, 15);
        assert_eq!(NEXTHOP_GRP_TYPE_MPATH, 0);
    }
}
