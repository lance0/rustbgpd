//! Router Solicitation / Router Advertisement grammar (RFC 4861 §4.1, §4.2)
//! and the receive validation of §6.1.1 and §6.1.2.
//!
//! Pure functions over the `ICMPv6` message as a raw `ICMPv6` socket returns it
//! (the IPv6 header stripped). The kernel verifies the `ICMPv6` checksum before
//! delivering to a raw `ICMPv6` socket and fills it in on transmit, so neither
//! direction handles it here.

use std::net::Ipv6Addr;

pub(crate) const ND_ROUTER_SOLICIT: u8 = 133;
pub(crate) const ND_ROUTER_ADVERT: u8 = 134;

/// RFC 4861 §6.1.2: an RA is at least 16 octets.
const RA_MIN_LEN: usize = 16;
/// RFC 4861 §6.1.1: an RS is at least 8 octets.
const RS_MIN_LEN: usize = 8;
/// RFC 4861 §4.6.1 Source Link-Layer Address option.
const OPT_SOURCE_LLADDR: u8 = 1;
/// RFC 4861 §6.1.1, §6.1.2: Neighbor Discovery packets must arrive with the
/// IPv6 Hop Limit a router sends them with, proving they did not cross one.
pub(crate) const ND_HOP_LIMIT: u8 = 255;

/// A validated Neighbor Discovery message this engine acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NdMessage {
    RouterAdvertisement { router_lifetime_secs: u16 },
    RouterSolicitation,
}

/// Why a received packet was discarded. Each reason has its own counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DropReason {
    /// The IPv6 Hop Limit was not 255, or the kernel did not report it.
    HopLimit,
    /// An RA whose IPv6 source is not link-local.
    SourceNotLinkLocal,
    /// ICMP code other than 0.
    NonZeroCode,
    /// Shorter than the message's fixed part.
    TooShort,
    /// An option with length 0 or one that runs past the end of the packet.
    MalformedOption,
    /// An RS from the unspecified address carrying a Source Link-Layer
    /// Address option (RFC 4861 §6.1.1).
    UnspecifiedSourceWithLinkLayerAddress,
    /// An `ICMPv6` type other than RS or RA (the socket filter passes only those).
    UnexpectedType,
    /// An RA whose source address is assigned to the receiving interface:
    /// this router's own advertisement or another local advertiser's.
    OwnAddress,
    /// An RA from a new source while the interface's candidate table is full.
    CandidateLimit,
    /// Read while the link was confirmed down, or before the latest
    /// Down→Up or recreation: it describes a link that no longer exists.
    StaleLink,
    /// The interface's address list could not be read, so the RA's source
    /// cannot be checked against our own addresses. Never treated as "not
    /// ours" or as "ours": the RA is skipped and state is left alone.
    AddressInventoryUnavailable,
}

impl DropReason {
    pub const ALL: [Self; 11] = [
        Self::HopLimit,
        Self::SourceNotLinkLocal,
        Self::NonZeroCode,
        Self::TooShort,
        Self::MalformedOption,
        Self::UnspecifiedSourceWithLinkLayerAddress,
        Self::UnexpectedType,
        Self::OwnAddress,
        Self::CandidateLimit,
        Self::StaleLink,
        Self::AddressInventoryUnavailable,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::HopLimit => "hop_limit",
            Self::SourceNotLinkLocal => "source_not_link_local",
            Self::NonZeroCode => "non_zero_code",
            Self::TooShort => "too_short",
            Self::MalformedOption => "malformed_option",
            Self::UnspecifiedSourceWithLinkLayerAddress => "unspecified_source_with_lladdr",
            Self::UnexpectedType => "unexpected_type",
            Self::OwnAddress => "own_address",
            Self::CandidateLimit => "candidate_limit",
            Self::StaleLink => "stale_link",
            Self::AddressInventoryUnavailable => "address_inventory_unavailable",
        }
    }
}

/// Validate one received `ICMPv6` message per RFC 4861 §6.1.1 (RS) and §6.1.2
/// (RA). `hop_limit` is the `IPV6_HOPLIMIT` ancillary value; `None` (the
/// kernel did not report it) is a discard, never an assumed 255.
pub(crate) fn parse(
    icmp: &[u8],
    source: Ipv6Addr,
    hop_limit: Option<u8>,
) -> Result<NdMessage, DropReason> {
    let (&msg_type, rest) = icmp.split_first().ok_or(DropReason::TooShort)?;
    let min_len = match msg_type {
        ND_ROUTER_ADVERT => RA_MIN_LEN,
        ND_ROUTER_SOLICIT => RS_MIN_LEN,
        _ => return Err(DropReason::UnexpectedType),
    };
    if hop_limit != Some(ND_HOP_LIMIT) {
        return Err(DropReason::HopLimit);
    }
    if rest.first().copied().ok_or(DropReason::TooShort)? != 0 {
        return Err(DropReason::NonZeroCode);
    }
    if icmp.len() < min_len {
        return Err(DropReason::TooShort);
    }
    let has_source_lladdr = scan_options(&icmp[min_len..])?;
    if msg_type == ND_ROUTER_ADVERT {
        if !source.is_unicast_link_local() {
            return Err(DropReason::SourceNotLinkLocal);
        }
        Ok(NdMessage::RouterAdvertisement {
            router_lifetime_secs: u16::from_be_bytes([icmp[6], icmp[7]]),
        })
    } else {
        if source.is_unspecified() && has_source_lladdr {
            return Err(DropReason::UnspecifiedSourceWithLinkLayerAddress);
        }
        Ok(NdMessage::RouterSolicitation)
    }
}

/// Walk the TLV options. Every option needs a non-zero length (in units of 8
/// octets) that stays inside the packet. Returns whether a Source Link-Layer
/// Address option is present.
fn scan_options(mut options: &[u8]) -> Result<bool, DropReason> {
    let mut source_lladdr = false;
    while !options.is_empty() {
        let [kind, units, ..] = *options else {
            return Err(DropReason::MalformedOption);
        };
        let len = usize::from(units) * 8;
        if len == 0 || len > options.len() {
            return Err(DropReason::MalformedOption);
        }
        source_lladdr |= kind == OPT_SOURCE_LLADDR;
        options = &options[len..];
    }
    Ok(source_lladdr)
}

/// The fixed RA template of ADR-0142: unspecified current hop limit, no M/O
/// flags, unspecified reachable and retransmit timers, no prefix options, and
/// a Source Link-Layer Address option when the interface has a MAC address.
pub(crate) fn encode_router_advertisement(
    router_lifetime_secs: u16,
    source_lladdr: Option<[u8; 6]>,
) -> Vec<u8> {
    let mut out = vec![0u8; RA_MIN_LEN];
    out[0] = ND_ROUTER_ADVERT;
    out[6..8].copy_from_slice(&router_lifetime_secs.to_be_bytes());
    push_source_lladdr(&mut out, source_lladdr);
    out
}

pub(crate) fn encode_router_solicitation(source_lladdr: Option<[u8; 6]>) -> Vec<u8> {
    let mut out = vec![0u8; RS_MIN_LEN];
    out[0] = ND_ROUTER_SOLICIT;
    push_source_lladdr(&mut out, source_lladdr);
    out
}

fn push_source_lladdr(out: &mut Vec<u8>, lladdr: Option<[u8; 6]>) {
    if let Some(mac) = lladdr {
        out.extend_from_slice(&[OPT_SOURCE_LLADDR, 1]);
        out.extend_from_slice(&mac);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];

    fn ll() -> Ipv6Addr {
        "fe80::a".parse().unwrap()
    }

    fn ra() -> Vec<u8> {
        encode_router_advertisement(30, Some(MAC))
    }

    #[test]
    fn valid_ra_and_rs_parse() {
        assert_eq!(
            parse(&ra(), ll(), Some(255)),
            Ok(NdMessage::RouterAdvertisement {
                router_lifetime_secs: 30
            })
        );
        let rs = encode_router_solicitation(Some(MAC));
        assert_eq!(
            parse(&rs, ll(), Some(255)),
            Ok(NdMessage::RouterSolicitation)
        );
        // An RS from the unspecified address without the option is valid.
        let rs = encode_router_solicitation(None);
        assert_eq!(
            parse(&rs, Ipv6Addr::UNSPECIFIED, Some(255)),
            Ok(NdMessage::RouterSolicitation)
        );
    }

    #[test]
    fn ra_template_is_fixed() {
        let ra = encode_router_advertisement(30, Some(MAC));
        assert_eq!(ra.len(), 24);
        assert_eq!(&ra[..2], &[134, 0]);
        assert_eq!(ra[4], 0, "current hop limit unspecified");
        assert_eq!(ra[5], 0, "no M/O flags");
        assert_eq!(&ra[6..8], &30u16.to_be_bytes());
        assert_eq!(&ra[8..16], &[0; 8], "reachable/retrans unspecified");
        assert_eq!(&ra[16..18], &[1, 1], "only the SLLA option");
        assert_eq!(&ra[18..], &MAC);
    }

    #[test]
    fn hop_limit_254_dropped() {
        assert_eq!(parse(&ra(), ll(), Some(254)), Err(DropReason::HopLimit));
        assert_eq!(parse(&ra(), ll(), None), Err(DropReason::HopLimit));
        let rs = encode_router_solicitation(None);
        assert_eq!(parse(&rs, ll(), Some(254)), Err(DropReason::HopLimit));
    }

    #[test]
    fn global_source_ra_dropped() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            parse(&ra(), global, Some(255)),
            Err(DropReason::SourceNotLinkLocal)
        );
        assert_eq!(
            parse(&ra(), Ipv6Addr::UNSPECIFIED, Some(255)),
            Err(DropReason::SourceNotLinkLocal)
        );
    }

    #[test]
    fn non_zero_code_dropped() {
        let mut ra = ra();
        ra[1] = 1;
        assert_eq!(parse(&ra, ll(), Some(255)), Err(DropReason::NonZeroCode));
        let mut rs = encode_router_solicitation(None);
        rs[1] = 7;
        assert_eq!(parse(&rs, ll(), Some(255)), Err(DropReason::NonZeroCode));
    }

    #[test]
    fn short_ra_dropped() {
        let ra = ra();
        assert_eq!(parse(&ra[..15], ll(), Some(255)), Err(DropReason::TooShort));
        assert_eq!(parse(&ra[..1], ll(), Some(255)), Err(DropReason::TooShort));
        assert_eq!(parse(&[], ll(), Some(255)), Err(DropReason::TooShort));
        let rs = encode_router_solicitation(None);
        assert_eq!(parse(&rs[..7], ll(), Some(255)), Err(DropReason::TooShort));
        // Exactly the fixed part, no options, is valid.
        assert!(parse(&ra[..16], ll(), Some(255)).is_ok());
    }

    #[test]
    fn zero_length_option_dropped() {
        let mut ra = ra();
        ra[17] = 0;
        assert_eq!(
            parse(&ra, ll(), Some(255)),
            Err(DropReason::MalformedOption)
        );
    }

    #[test]
    fn truncated_option_dropped() {
        let ra = ra();
        // Option claims 8 octets but only 7 remain.
        assert_eq!(
            parse(&ra[..23], ll(), Some(255)),
            Err(DropReason::MalformedOption)
        );
        // A lone option-type octet with no length.
        assert_eq!(
            parse(&ra[..17], ll(), Some(255)),
            Err(DropReason::MalformedOption)
        );
        // Length runs past the end.
        let mut long = ra.clone();
        long[17] = 2;
        assert_eq!(
            parse(&long, ll(), Some(255)),
            Err(DropReason::MalformedOption)
        );
        // The second of two options is the bad one.
        let mut two = ra.clone();
        two.extend_from_slice(&[5, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            parse(&two, ll(), Some(255)),
            Err(DropReason::MalformedOption)
        );
    }

    #[test]
    fn rs_from_unspecified_with_lladdr_dropped() {
        let rs = encode_router_solicitation(Some(MAC));
        assert_eq!(
            parse(&rs, Ipv6Addr::UNSPECIFIED, Some(255)),
            Err(DropReason::UnspecifiedSourceWithLinkLayerAddress)
        );
    }

    #[test]
    fn other_icmp_types_dropped() {
        let mut ra = ra();
        ra[0] = 135;
        assert_eq!(parse(&ra, ll(), Some(255)), Err(DropReason::UnexpectedType));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // Cheap stand-in for the absent root-crate fuzz harness: every prefix
        // and every single-byte mutation of a valid RA parses without panicking.
        let ra = ra();
        for len in 0..=ra.len() {
            let _ = parse(&ra[..len], ll(), Some(255));
        }
        for i in 0..ra.len() {
            for b in [0u8, 1, 0x7f, 0x80, 0xff] {
                let mut m = ra.clone();
                m[i] = b;
                let _ = parse(&m, ll(), Some(255));
            }
        }
    }
}
