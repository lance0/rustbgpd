//! `rbgp diff snapshot from-bmp` — convert a captured RFC 7854 BMP byte
//! stream carrying the RFC 8671 post-policy Adj-RIB-Out view into an
//! `rbgp-ribsnap/1` NDJSON snapshot for `rbgp diff advertised` (adapter
//! contract `from-bmp/1`, see docs/ribdiff.md).
//!
//! Input is an offline file of raw, concatenated BMP version 3 messages
//! (e.g. the TCP payload of the incumbent's BMP feed, captured from the
//! start of the session). Streaming-socket ingestion is out of scope for
//! this adapter — capture to a file first.
//!
//! View contract (RFC 8671): only Route Monitoring messages whose
//! per-peer header carries O=1 (Adj-RIB-Out) and L=1 (post-policy)
//! contribute routes. O=0 messages are the pre-policy Adj-RIB-In view
//! that most feeds also carry; they are skipped with a note. O=1 with
//! L=0 is the *pre-policy* Adj-RIB-Out — a different view whose
//! comparison against a post-policy Adj-RIB-Out would report every
//! export-policy effect as divergence — so it refuses the conversion
//! (exit 2), matching the from-mrt `--view` refusal pattern. O/L flags
//! on Peer Up / Peer Down are not view selectors and are ignored there.
//!
//! Completeness and generations (RFC 7854 §5, §9): announce/withdraw
//! state is kept per (connection generation, peer, family, NLRI, source
//! path ID); a later update for the same key supersedes an earlier one,
//! so live updates interleaved with the initial dump fold correctly. A
//! (peer, family) is complete only once its End-of-RIB arrives in the
//! current generation. A new Initiation (reconnect) invalidates all
//! state; a Peer Up resets the peer; a Peer Down discards it — old and
//! new generations are never mixed. Missing End-of-RIB at end of input
//! refuses the conversion: `rbgp-ribsnap/1` carries no per-peer
//! completeness field, so an incomplete peer must not be emitted under
//! a counted trailer that would read as complete.
//!
//! Negotiated state comes from the Peer Up OPENs: Add-Path is in effect
//! for a family iff the incumbent's sent OPEN advertised send (2/3) and
//! the peer's received OPEN advertised receive (1/3) for it (RFC 7911);
//! AS_PATH width follows each message's per-peer-header A flag. RFC 8671
//! stat types 15/17 arriving after End-of-RIB are cross-checked against
//! the folded route counts (completeness never *requires* them; a
//! mismatch means a decode gap and refuses the conversion).
//!
//! Fail-closed: any framing error, embedded-UPDATE decode error,
//! truncation, out-of-protocol sequence, or exceeded hard bound exits 2
//! with nothing on stdout — a half-converted snapshot with a valid
//! trailer cannot exist. RFC 6793 AS_PATH/AS4_PATH (types 2/17) and
//! AGGREGATOR/AS4_AGGREGATOR (types 7/18) pairs normalize to one canonical
//! path and 8-byte type-7 aggregator. Other unknown and untyped attributes
//! preserve their value bytes and semantic flags in `unknown_attrs`, never
//! silently dropped.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use rustbgpd_wire::attribute::{AsPath, MpReachNlri, MpUnreachNlri, PathAttribute};
use rustbgpd_wire::capability::{AddPathMode, Afi, Capability, Safi};
use rustbgpd_wire::constants::{EXTENDED_MAX_MESSAGE_LEN, HEADER_LEN, attr_flags, attr_type};
use rustbgpd_wire::header::{BgpHeader, MessageType};
use rustbgpd_wire::nlri::Prefix;
use rustbgpd_wire::open::OpenMessage;
use rustbgpd_wire::update::UpdateMessage;

use super::ribsnap::{Cursor, EXIT_OK, EXIT_REFUSED, SnapRoute, route_record_json};

// BMP message types (RFC 7854 §4.1).
const BMP_MSG_ROUTE_MONITORING: u8 = 0;
const BMP_MSG_STATS_REPORT: u8 = 1;
const BMP_MSG_PEER_DOWN: u8 = 2;
const BMP_MSG_PEER_UP: u8 = 3;
const BMP_MSG_INITIATION: u8 = 4;
const BMP_MSG_TERMINATION: u8 = 5;
const BMP_MSG_ROUTE_MIRRORING: u8 = 6;

// Per-peer header flags (RFC 7854 §4.2, RFC 8671 §4).
const PEER_FLAG_V: u8 = 0x80;
const PEER_FLAG_L: u8 = 0x40;
const PEER_FLAG_A: u8 = 0x20;
const PEER_FLAG_O: u8 = 0x10;

/// BMP common header: version(1) + length(4) + type(1).
const BMP_COMMON_HEADER_LEN: usize = 6;

/// RFC 8671 stat types cross-checked after End-of-RIB.
const STAT_ADJ_RIB_OUT_POST: u16 = 15;
const STAT_ADJ_RIB_OUT_POST_PER_AFI: u16 = 17;

/// Hard resource bounds. Deliberately constants, not flags: exceeding
/// any of them refuses the conversion (exit 2) — a bound is a safety
/// property, not a tuning knob. Attribute-per-path and message-size
/// bounds are additionally enforced by the BGP wire decoder itself.
#[derive(Clone, Copy)]
struct Limits {
    /// Maximum capture bytes read.
    max_input_bytes: u64,
    /// Maximum single BMP message length (the common-header length
    /// field). The largest legitimate message is a Route Monitoring
    /// around one extended UPDATE (~64 KiB); 1 MiB leaves TLV headroom.
    max_bmp_message_len: usize,
    /// Maximum monitored peers.
    max_peers: usize,
    /// Maximum retained routes across all peers.
    max_routes: usize,
    /// Maximum distinct source path IDs per (peer, family, NLRI).
    max_paths_per_nlri: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1 << 30,
            max_bmp_message_len: 1 << 20,
            max_peers: 4096,
            max_routes: 4_000_000,
            max_paths_per_nlri: 64,
        }
    }
}

/// Options for `rbgp diff snapshot from-bmp`.
pub struct FromBmpOpts<'a> {
    /// Path to the captured BMP byte stream.
    pub file: &'a Path,
    /// Peers to emit (empty = every complete global-instance peer).
    /// Every listed peer must be present and complete.
    pub peers: &'a [String],
    /// Free-form provenance label appended to the header `source`.
    pub source: Option<&'a str>,
    /// Capture-round generation stamped into the snapshot header.
    pub generation: u64,
}

/// Run the adapter: print the snapshot to stdout on success (notes to
/// stderr), an error to stderr on refusal, and return the exit code.
pub fn from_bmp(opts: &FromBmpOpts<'_>) -> i32 {
    match run(opts) {
        Ok((snapshot, notes)) => {
            for note in notes {
                eprintln!("note: {note}");
            }
            print!("{snapshot}");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("Error: {e}");
            EXIT_REFUSED
        }
    }
}

fn run(opts: &FromBmpOpts<'_>) -> Result<(String, Vec<String>), String> {
    run_with_limits(opts, Limits::default())
}

fn run_with_limits(
    opts: &FromBmpOpts<'_>,
    limits: Limits,
) -> Result<(String, Vec<String>), String> {
    let peer_filter: BTreeSet<IpAddr> = opts
        .peers
        .iter()
        .map(|p| {
            p.parse()
                .map_err(|e| format!("invalid --peer address {p:?}: {e}"))
        })
        .collect::<Result<_, _>>()?;
    let display = opts.file.display();
    let size = std::fs::metadata(opts.file)
        .map_err(|e| format!("cannot read {display}: {e}"))?
        .len();
    if size > limits.max_input_bytes {
        return Err(format!(
            "{display}: {size} bytes exceeds the input limit of {} bytes; refusing",
            limits.max_input_bytes
        ));
    }
    let data = std::fs::read(opts.file).map_err(|e| format!("cannot read {display}: {e}"))?;

    let mut importer = Importer::default();
    let mut offset = 0_usize;
    let mut index = 0_usize;
    while offset < data.len() {
        index += 1;
        let context = |e: String| format!("{display}: BMP message #{index} at byte {offset}: {e}");
        let rest = &data[offset..];
        if rest.len() < BMP_COMMON_HEADER_LEN {
            return Err(context(format!(
                "truncated common header ({} trailing bytes)",
                rest.len()
            )));
        }
        let version = rest[0];
        if version != 3 {
            return Err(context(format!(
                "BMP version {version} is not supported (this adapter reads RFC 7854 \
                 version 3 streams; if the byte is not 3 or 4, the file is likely not \
                 a raw BMP capture)"
            )));
        }
        let length = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
        let msg_type = rest[5];
        if length < BMP_COMMON_HEADER_LEN {
            return Err(context(format!(
                "message length {length} below header size"
            )));
        }
        if length > limits.max_bmp_message_len {
            return Err(context(format!(
                "message length {length} exceeds the {} byte limit; refusing",
                limits.max_bmp_message_len
            )));
        }
        if length > rest.len() {
            return Err(context(format!(
                "truncated: message declares {length} bytes but only {} remain \
                 (the capture is cut mid-message)",
                rest.len()
            )));
        }
        let body = &rest[BMP_COMMON_HEADER_LEN..length];
        importer.handle(msg_type, body, limits).map_err(context)?;
        offset += length;
    }

    importer.finish(opts, &peer_filter)
}

/// Family key for the state maps — the two families `rbgp-ribsnap/1`
/// can express.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Fam {
    V4Unicast,
    V6Unicast,
}

impl Fam {
    fn from_afi_safi(afi: Afi, safi: Safi) -> Option<Self> {
        match (afi, safi) {
            (Afi::Ipv4, Safi::Unicast) => Some(Self::V4Unicast),
            (Afi::Ipv6, Safi::Unicast) => Some(Self::V6Unicast),
            _ => None,
        }
    }

    fn from_wire(afi: u16, safi: u8) -> Option<Self> {
        match (afi, safi) {
            (1, 1) => Some(Self::V4Unicast),
            (2, 1) => Some(Self::V6Unicast),
            _ => None,
        }
    }

    fn wire(self) -> (Afi, Safi) {
        match self {
            Self::V4Unicast => (Afi::Ipv4, Safi::Unicast),
            Self::V6Unicast => (Afi::Ipv6, Safi::Unicast),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::V4Unicast => "ipv4_unicast",
            Self::V6Unicast => "ipv6_unicast",
        }
    }
}

/// State key: (family, NLRI, source-local RFC 7911 path ID). Path IDs
/// are internal keys only — they select which announcement a later
/// update or withdraw supersedes, and are never compared downstream.
type RouteKey = (Fam, IpAddr, u8, u32);

/// One monitored peer's state within the current connection generation.
struct PeerState {
    asn: u32,
    /// Families where Add-Path is in effect incumbent→peer (path IDs
    /// present in the encapsulated UPDATEs).
    addpath: BTreeSet<Fam>,
    /// Families that must reach End-of-RIB for the peer to be complete:
    /// the unicast families negotiated in the OPENs, plus any family
    /// with observed Route Monitoring activity.
    expected: BTreeSet<Fam>,
    /// Families whose End-of-RIB has been seen in this generation.
    eor: BTreeSet<Fam>,
    routes: BTreeMap<RouteKey, SnapRoute>,
    /// Non-unicast NLRI carriers skipped for this peer (not expressible
    /// in `rbgp-ribsnap/1`).
    non_unicast_skipped: u64,
}

/// Decoded RFC 7854 §4.2 per-peer header (fields the adapter uses).
struct PerPeerHeader {
    peer_type: u8,
    flags: u8,
    distinguisher: u64,
    addr: IpAddr,
    asn: u32,
}

fn parse_per_peer_header(cur: &mut Cursor<'_>) -> Result<PerPeerHeader, String> {
    let peer_type = cur.read_u8()?;
    let flags = cur.read_u8()?;
    let distinguisher = cur.read_u64()?;
    let raw = cur.take(16)?;
    let addr = if flags & PEER_FLAG_V != 0 {
        IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(raw).expect("length checked"),
        ))
    } else {
        IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]))
    };
    let asn = cur.read_u32()?;
    let _bgp_id = cur.read_u32()?;
    let _timestamp_secs = cur.read_u32()?;
    let _timestamp_usecs = cur.read_u32()?;
    Ok(PerPeerHeader {
        peer_type,
        flags,
        distinguisher,
        addr,
        asn,
    })
}

#[derive(Default)]
struct Importer {
    /// Connection generation: bumped by every Initiation; 0 = none seen.
    generation: u64,
    /// A Termination was seen; only a new Initiation may follow.
    terminated: bool,
    peers: BTreeMap<IpAddr, PeerState>,
    /// Non-global instance peers (peer type != 0 or distinguisher != 0):
    /// VPN views `rbgp-ribsnap/1` cannot express; skipped entirely.
    ignored_instance_peers: BTreeSet<IpAddr>,
    /// Total retained routes across peers (bound by `max_routes`).
    total_routes: usize,
    /// Pre-policy Adj-RIB-In Route Monitoring messages skipped (O=0).
    rib_in_skipped: u64,
    /// Route Mirroring messages skipped.
    mirrored_skipped: u64,
}

impl Importer {
    fn handle(&mut self, msg_type: u8, body: &[u8], limits: Limits) -> Result<(), String> {
        if msg_type == BMP_MSG_INITIATION {
            // Reconnect: a new connection generation invalidates all
            // prior state — old and new are never mixed.
            self.generation += 1;
            self.terminated = false;
            self.peers.clear();
            self.ignored_instance_peers.clear();
            self.total_routes = 0;
            return Ok(());
        }
        if self.generation == 0 {
            return Err(
                "message before the Initiation message — the capture must start at the \
                 beginning of a BMP session (a mid-stream capture is missing the Peer Up \
                 negotiation state and cannot be decoded soundly)"
                    .to_string(),
            );
        }
        if self.terminated {
            return Err("message after a Termination message without a new Initiation".to_string());
        }
        match msg_type {
            BMP_MSG_TERMINATION => {
                self.terminated = true;
                Ok(())
            }
            BMP_MSG_PEER_UP => self.handle_peer_up(body, limits),
            BMP_MSG_PEER_DOWN => self.handle_peer_down(body),
            BMP_MSG_ROUTE_MONITORING => self.handle_route_monitoring(body, limits),
            BMP_MSG_STATS_REPORT => self.handle_stats(body),
            BMP_MSG_ROUTE_MIRRORING => {
                self.mirrored_skipped += 1;
                Ok(())
            }
            other => Err(format!("unknown BMP message type {other}; refusing")),
        }
    }

    fn handle_peer_up(&mut self, body: &[u8], limits: Limits) -> Result<(), String> {
        let mut cur = Cursor::new(body);
        let pph = parse_per_peer_header(&mut cur)?;
        // O/L flags on Peer Up are NOT route-view selectors (RFC 8671
        // §5: receivers ignore them here) — only Route Monitoring
        // per-peer-header flags select the view.
        if pph.peer_type != 0 || pph.distinguisher != 0 {
            self.ignored_instance_peers.insert(pph.addr);
            return Ok(());
        }
        cur.take(20)?; // local address (16) + local port (2) + remote port (2)
        let sent_open =
            parse_open_pdu(&mut cur).map_err(|e| format!("peer {}: sent OPEN: {e}", pph.addr))?;
        let received_open = parse_open_pdu(&mut cur)
            .map_err(|e| format!("peer {}: received OPEN: {e}", pph.addr))?;
        // Trailing Information TLVs are ignored.

        // Negotiated unicast families: the intersection of both OPENs'
        // MP capabilities; a side with no MP capability is plain IPv4
        // unicast (RFC 4760).
        let expected: BTreeSet<Fam> = unicast_families(&sent_open)
            .intersection(&unicast_families(&received_open))
            .copied()
            .collect();
        // Add-Path is directional (RFC 7911 §4): path IDs appear in the
        // incumbent's UPDATEs toward this peer iff the incumbent's sent
        // OPEN advertised send AND the peer's received OPEN advertised
        // receive for the family.
        let sent_modes = addpath_modes(&sent_open);
        let received_modes = addpath_modes(&received_open);
        let addpath: BTreeSet<Fam> = expected
            .iter()
            .copied()
            .filter(|fam| {
                matches!(
                    sent_modes.get(fam),
                    Some(AddPathMode::Send | AddPathMode::Both)
                ) && matches!(
                    received_modes.get(fam),
                    Some(AddPathMode::Receive | AddPathMode::Both)
                )
            })
            .collect();

        // A repeated Peer Up resets the peer: prior routes and
        // End-of-RIB state belong to the previous peer generation.
        if let Some(old) = self.peers.remove(&pph.addr) {
            self.total_routes -= old.routes.len();
        } else if self.peers.len() >= limits.max_peers {
            return Err(format!(
                "more than {} monitored peers; refusing",
                limits.max_peers
            ));
        }
        self.peers.insert(
            pph.addr,
            PeerState {
                asn: pph.asn,
                addpath,
                expected,
                eor: BTreeSet::new(),
                routes: BTreeMap::new(),
                non_unicast_skipped: 0,
            },
        );
        Ok(())
    }

    fn handle_peer_down(&mut self, body: &[u8]) -> Result<(), String> {
        let mut cur = Cursor::new(body);
        let pph = parse_per_peer_header(&mut cur)?;
        if pph.peer_type != 0 || pph.distinguisher != 0 {
            return Ok(());
        }
        // Reason payload is irrelevant: the peer's Adj-RIB-Out ceased to
        // exist, so its state is invalidated. Without a later Peer Up it
        // contributes nothing to the snapshot.
        match self.peers.remove(&pph.addr) {
            Some(state) => {
                self.total_routes -= state.routes.len();
                Ok(())
            }
            None => Err(format!(
                "Peer Down for peer {} without a Peer Up in this connection generation",
                pph.addr
            )),
        }
    }

    fn handle_route_monitoring(&mut self, body: &[u8], limits: Limits) -> Result<(), String> {
        let mut cur = Cursor::new(body);
        let pph = parse_per_peer_header(&mut cur)?;
        if pph.peer_type != 0
            || pph.distinguisher != 0
            || self.ignored_instance_peers.contains(&pph.addr)
        {
            // Instance-peer monitoring (VPN views) is skipped with the
            // peer itself.
            return Ok(());
        }
        if pph.flags & PEER_FLAG_O == 0 {
            // Pre-policy Adj-RIB-In monitoring (RFC 7854 default view):
            // most feeds carry it alongside; it is not the requested
            // view and is skipped, never folded.
            self.rib_in_skipped += 1;
            return Ok(());
        }
        if pph.flags & PEER_FLAG_L == 0 {
            return Err(format!(
                "peer {}: Route Monitoring carries the pre-policy Adj-RIB-Out view \
                 (O=1, L=0), which is not comparable against a post-policy \
                 Adj-RIB-Out: comparing it would report every export-policy effect \
                 as divergence (or mask one as expected). Configure the incumbent's \
                 BMP export for post-policy Adj-RIB-Out (RFC 8671, L=1) and \
                 re-capture.",
                pph.addr
            ));
        }
        let Some(state) = self.peers.get_mut(&pph.addr) else {
            return Err(format!(
                "Route Monitoring for peer {} without a Peer Up in this connection \
                 generation — negotiated Add-Path state is unknown, so the UPDATE \
                 cannot be decoded soundly",
                pph.addr
            ));
        };
        if state.asn != pph.asn {
            return Err(format!(
                "peer {}: per-peer header ASN {} conflicts with the Peer Up ASN {}",
                pph.addr, pph.asn, state.asn
            ));
        }
        // RFC 7854 §4.2: the A flag marks legacy 2-octet AS_PATH
        // encoding in the encapsulated message.
        let four_octet_as = pph.flags & PEER_FLAG_A == 0;
        fold_update(
            state,
            &mut self.total_routes,
            limits,
            four_octet_as,
            cur.remaining(),
        )
        .map_err(|e| format!("peer {}: {e}", pph.addr))
    }

    fn handle_stats(&mut self, body: &[u8]) -> Result<(), String> {
        let mut cur = Cursor::new(body);
        let pph = parse_per_peer_header(&mut cur)?;
        if pph.peer_type != 0 || pph.distinguisher != 0 {
            return Ok(());
        }
        let Some(state) = self.peers.get(&pph.addr) else {
            return Err(format!(
                "Stats Report for peer {} without a Peer Up in this connection generation",
                pph.addr
            ));
        };
        let count = cur.read_u32()?;
        for _ in 0..count {
            let stat_type = cur.read_u16()?;
            let len = cur.read_u16()? as usize;
            let value = cur.take(len)?;
            match stat_type {
                // RFC 8671 type 17: per-AFI/SAFI post-policy Adj-RIB-Out
                // gauge. After that family's End-of-RIB the folded state
                // must match it exactly (same ordered stream) — a
                // mismatch means a decode gap.
                STAT_ADJ_RIB_OUT_POST_PER_AFI => {
                    let [a0, a1, s, v @ ..] = value else {
                        return Err(format!("stat type 17 length {len} != 11"));
                    };
                    let v: [u8; 8] = v
                        .try_into()
                        .map_err(|_| format!("stat type 17 length {len} != 11"))?;
                    let reported = u64::from_be_bytes(v);
                    let Some(fam) = Fam::from_wire(u16::from_be_bytes([*a0, *a1]), *s) else {
                        continue; // non-unicast family gauge: not tracked
                    };
                    if !state.eor.contains(&fam) {
                        continue; // cross-check applies only after End-of-RIB
                    }
                    let folded = state.routes.keys().filter(|(f, ..)| *f == fam).count() as u64;
                    if folded != reported {
                        return Err(format!(
                            "peer {} family {}: RFC 8671 stat 17 reports {reported} \
                             post-policy Adj-RIB-Out routes but the folded state holds \
                             {folded} — a Route Monitoring message was missed or \
                             misdecoded; refusing",
                            pph.addr,
                            fam.name()
                        ));
                    }
                }
                // RFC 8671 type 15: total post-policy Adj-RIB-Out gauge.
                // Only checkable when every family the peer carries is a
                // tracked unicast family that has reached End-of-RIB.
                STAT_ADJ_RIB_OUT_POST => {
                    let v: [u8; 8] = value
                        .try_into()
                        .map_err(|_| format!("stat type 15 length {len} != 8"))?;
                    let reported = u64::from_be_bytes(v);
                    if state.non_unicast_skipped > 0
                        || !state.expected.iter().all(|f| state.eor.contains(f))
                    {
                        continue;
                    }
                    let folded = state.routes.len() as u64;
                    if folded != reported {
                        return Err(format!(
                            "peer {}: RFC 8671 stat 15 reports {reported} post-policy \
                             Adj-RIB-Out routes but the folded state holds {folded} — \
                             a Route Monitoring message was missed or misdecoded; \
                             refusing",
                            pph.addr
                        ));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Validate completeness and render the snapshot.
    fn finish(
        self,
        opts: &FromBmpOpts<'_>,
        peer_filter: &BTreeSet<IpAddr>,
    ) -> Result<(String, Vec<String>), String> {
        let display = opts.file.display();
        if self.generation == 0 {
            return Err(format!(
                "{display}: no BMP Initiation message found — not a BMP capture, or \
                 the capture does not start at the beginning of a session"
            ));
        }
        let mut selected: Vec<(IpAddr, &PeerState)> = Vec::new();
        if peer_filter.is_empty() {
            selected.extend(self.peers.iter().map(|(a, s)| (*a, s)));
        } else {
            for addr in peer_filter {
                let Some(state) = self.peers.get(addr) else {
                    return Err(format!(
                        "{display}: peer {addr} has no state in the capture's final \
                         connection generation (no Peer Up, or invalidated by a \
                         Peer Down or reconnect); refusing"
                    ));
                };
                selected.push((*addr, state));
            }
        }
        if selected.is_empty() {
            return Err(format!(
                "{display}: no global-instance peers with post-policy Adj-RIB-Out \
                 state in the capture; nothing to emit"
            ));
        }
        for (addr, state) in &selected {
            for fam in &state.expected {
                if !state.eor.contains(fam) {
                    return Err(format!(
                        "{display}: peer {addr} family {}: End-of-RIB not seen in the \
                         current connection generation — the post-policy Adj-RIB-Out \
                         dump is incomplete and equality must never be asserted from \
                         it. Re-capture a complete stream (or exclude the peer with \
                         --peer).",
                        fam.name()
                    ));
                }
            }
        }

        let mut out = String::new();
        let mut source = "from-bmp/1 view=adj-rib-out-post-policy".to_string();
        if let Some(label) = opts.source {
            source.push(' ');
            source.push_str(label);
        }
        let header = serde_json::json!({
            "record": "header",
            "schema": super::diff::SNAPSHOT_SCHEMA,
            "source": source,
            "generation": opts.generation,
        });
        out.push_str(&header.to_string());
        out.push('\n');
        let mut count = 0_usize;
        for (addr, state) in &selected {
            for ((_, prefix, len, _), route) in &state.routes {
                out.push_str(&route_record_json(*addr, state.asn, *prefix, *len, route));
                out.push('\n');
                count += 1;
            }
        }
        let trailer = serde_json::json!({"record": "trailer", "routes": count});
        out.push_str(&trailer.to_string());
        out.push('\n');

        let mut notes = Vec::new();
        if self.rib_in_skipped > 0 {
            notes.push(format!(
                "{} pre-policy Adj-RIB-In Route Monitoring messages (O=0) ignored — \
                 from-bmp imports the post-policy Adj-RIB-Out view only",
                self.rib_in_skipped
            ));
        }
        if self.mirrored_skipped > 0 {
            notes.push(format!(
                "{} Route Mirroring messages ignored",
                self.mirrored_skipped
            ));
        }
        for addr in &self.ignored_instance_peers {
            notes.push(format!(
                "instance peer {addr} skipped (non-global peer type or distinguisher; \
                 rbgp-ribsnap/1 carries the global unicast view only)"
            ));
        }
        for (addr, state) in &selected {
            if state.non_unicast_skipped > 0 {
                notes.push(format!(
                    "peer {addr}: {} non-unicast NLRI carriers skipped \
                     (rbgp-ribsnap/1 carries IPv4/IPv6 unicast only)",
                    state.non_unicast_skipped
                ));
            }
        }
        Ok((out, notes))
    }
}

/// Decode one full BGP OPEN PDU (with 19-byte header) from the cursor
/// and advance past it.
fn parse_open_pdu(cur: &mut Cursor<'_>) -> Result<OpenMessage, String> {
    let mut buf = cur.remaining();
    let header =
        BgpHeader::decode(&mut buf, EXTENDED_MAX_MESSAGE_LEN).map_err(|e| e.to_string())?;
    if header.message_type != MessageType::Open {
        return Err(format!("expected an OPEN, got {:?}", header.message_type));
    }
    let body_len = usize::from(header.length) - HEADER_LEN;
    let open = OpenMessage::decode(&mut buf, body_len).map_err(|e| e.to_string())?;
    cur.take(usize::from(header.length))?;
    Ok(open)
}

/// Unicast families a speaker's OPEN supports: its MP capabilities
/// filtered to IPv4/IPv6 unicast, or plain IPv4 unicast when it carries
/// no MP capability at all (RFC 4760 §8).
fn unicast_families(open: &OpenMessage) -> BTreeSet<Fam> {
    let mut families = BTreeSet::new();
    let mut saw_mp = false;
    for capability in &open.capabilities {
        if let Capability::MultiProtocol { afi, safi } = capability {
            saw_mp = true;
            if let Some(fam) = Fam::from_afi_safi(*afi, *safi) {
                families.insert(fam);
            }
        }
    }
    if !saw_mp {
        families.insert(Fam::V4Unicast);
    }
    families
}

/// Per-family Add-Path modes advertised in an OPEN (last entry wins).
fn addpath_modes(open: &OpenMessage) -> BTreeMap<Fam, AddPathMode> {
    let mut modes = BTreeMap::new();
    for capability in &open.capabilities {
        if let Capability::AddPath(families) = capability {
            for family in families {
                if let Some(fam) = Fam::from_afi_safi(family.afi, family.safi) {
                    modes.insert(fam, family.send_receive);
                }
            }
        }
    }
    modes
}

/// Decode and fold one encapsulated BGP UPDATE into the peer's state.
fn fold_update(
    state: &mut PeerState,
    total_routes: &mut usize,
    limits: Limits,
    four_octet_as: bool,
    pdu: &[u8],
) -> Result<(), String> {
    let mut buf = pdu;
    let header =
        BgpHeader::decode(&mut buf, EXTENDED_MAX_MESSAGE_LEN).map_err(|e| e.to_string())?;
    if header.message_type != MessageType::Update {
        return Err(format!(
            "Route Monitoring carries a {:?} PDU, expected UPDATE",
            header.message_type
        ));
    }
    if usize::from(header.length) != pdu.len() {
        return Err(format!(
            "encapsulated UPDATE declares {} bytes but the message carries {} — \
             framing is corrupt",
            header.length,
            pdu.len()
        ));
    }
    let body_len = usize::from(header.length) - HEADER_LEN;
    let update = UpdateMessage::decode(&mut buf, body_len).map_err(|e| e.to_string())?;

    // RFC 4724 §2: the IPv4-unicast End-of-RIB is a completely empty
    // UPDATE.
    if update.withdrawn_routes.is_empty()
        && update.path_attributes.is_empty()
        && update.nlri.is_empty()
    {
        state.expected.insert(Fam::V4Unicast);
        state.eor.insert(Fam::V4Unicast);
        return Ok(());
    }

    let addpath_v4 = state.addpath.contains(&Fam::V4Unicast);
    let addpath_families: Vec<(Afi, Safi)> = state.addpath.iter().map(|f| f.wire()).collect();
    let parsed = update
        .parse(four_octet_as, addpath_v4, &addpath_families)
        .map_err(|e| e.to_string())?;

    // RFC 4724 §2: a non-IPv4 End-of-RIB is an UPDATE whose only
    // content is an empty MP_UNREACH_NLRI naming the family.
    if update.withdrawn_routes.is_empty()
        && update.nlri.is_empty()
        && let [PathAttribute::MpUnreachNlri(mp)] = parsed.attributes.as_slice()
        && mp_unreach_nlri_count(mp) == 0
    {
        match Fam::from_afi_safi(mp.afi, mp.safi) {
            Some(fam) => {
                state.expected.insert(fam);
                state.eor.insert(fam);
            }
            None => state.non_unicast_skipped += 1,
        }
        return Ok(());
    }

    let mut base = SnapRoute::default();
    let mut mp_reach: Option<&MpReachNlri> = None;
    let mut mp_unreach: Option<&MpUnreachNlri> = None;
    for attribute in &parsed.attributes {
        convert_attribute(attribute, &mut base, &mut mp_reach, &mut mp_unreach)?;
    }

    // Body IPv4-unicast withdrawals and announcements.
    for entry in &parsed.withdrawn {
        remove_route(
            state,
            total_routes,
            Fam::V4Unicast,
            IpAddr::V4(entry.prefix.addr),
            entry.prefix.len,
            entry.path_id,
        );
    }
    for entry in &parsed.announced {
        let route = clone_route(&base, base.next_hop, addpath_v4.then_some(entry.path_id));
        insert_route(
            state,
            total_routes,
            limits,
            (
                Fam::V4Unicast,
                IpAddr::V4(entry.prefix.addr),
                entry.prefix.len,
                entry.path_id,
            ),
            route,
        )?;
    }

    // MP withdrawals and announcements (unicast families only).
    if let Some(mp) = mp_unreach {
        match Fam::from_afi_safi(mp.afi, mp.safi) {
            Some(fam) => {
                for entry in &mp.withdrawn {
                    let (addr, len) = split_prefix(entry.prefix);
                    remove_route(state, total_routes, fam, addr, len, entry.path_id);
                }
            }
            None => state.non_unicast_skipped += 1,
        }
    }
    if let Some(mp) = mp_reach {
        match Fam::from_afi_safi(mp.afi, mp.safi) {
            Some(fam) => {
                let addpath = state.addpath.contains(&fam);
                for entry in &mp.announced {
                    let (addr, len) = split_prefix(entry.prefix);
                    let route =
                        clone_route(&base, Some(mp.next_hop), addpath.then_some(entry.path_id));
                    insert_route(
                        state,
                        total_routes,
                        limits,
                        (fam, addr, len, entry.path_id),
                        route,
                    )?;
                }
            }
            None => state.non_unicast_skipped += 1,
        }
    }
    Ok(())
}

fn split_prefix(prefix: Prefix) -> (IpAddr, u8) {
    match prefix {
        Prefix::V4(p) => (IpAddr::V4(p.addr), p.len),
        Prefix::V6(p) => (IpAddr::V6(p.addr), p.len),
    }
}

/// Total NLRI units carried by an MP_UNREACH_NLRI across all its family
/// shapes (0 = the End-of-RIB form).
fn mp_unreach_nlri_count(mp: &MpUnreachNlri) -> usize {
    mp.withdrawn.len()
        + mp.flowspec_withdrawn.len()
        + mp.evpn_withdrawn.len()
        + mp.bgpls_withdrawn.len()
        + mp.vpn_withdrawn.len()
        + mp.labeled_withdrawn.len()
        + mp.rtc_withdrawn.len()
}

/// Fold one decoded path attribute into the shared `SnapRoute` template.
///
/// Attributes with typed snapshot fields map directly. The wire decoder has
/// already combined RFC 6793 types 2/17 and 7/18; this converter stores the
/// canonical AS path and emits the canonical 8-byte type-7 aggregator.
/// Attributes the snapshot does not type (ORIGINATOR_ID, CLUSTER_LIST, OTC,
/// and anything the wire decoder itself leaves untyped) retain their value
/// bytes and semantic flags in `unknown_attrs`. The EXTENDED_LENGTH bit is
/// cleared because it is an encoding artifact, not attribute semantics.
fn convert_attribute<'a>(
    attribute: &'a PathAttribute,
    base: &mut SnapRoute,
    mp_reach: &mut Option<&'a MpReachNlri>,
    mp_unreach: &mut Option<&'a MpUnreachNlri>,
) -> Result<(), String> {
    match attribute {
        PathAttribute::Origin(origin) => base.origin = Some(*origin as u8),
        PathAttribute::AsPath(path) => base.as_path = flatten_as_path(path),
        PathAttribute::NextHop(next_hop) => base.next_hop = Some(IpAddr::V4(*next_hop)),
        PathAttribute::Med(med) => base.med = Some(*med),
        PathAttribute::LocalPref(local_pref) => base.local_pref = Some(*local_pref),
        PathAttribute::Communities(communities) => base.communities = communities.clone(),
        PathAttribute::ExtendedCommunities(communities) => {
            base.extended_communities = communities.iter().map(|c| c.as_u64()).collect();
        }
        PathAttribute::LargeCommunities(communities) => {
            base.large_communities = communities
                .iter()
                .map(|c| [c.global_admin, c.local_data1, c.local_data2])
                .collect();
        }
        PathAttribute::OriginatorId(id) => base.unknown_attrs.push((
            attr_flags::OPTIONAL,
            attr_type::ORIGINATOR_ID,
            id.octets().to_vec(),
        )),
        PathAttribute::ClusterList(clusters) => base.unknown_attrs.push((
            attr_flags::OPTIONAL,
            attr_type::CLUSTER_LIST,
            clusters.iter().flat_map(|c| c.octets()).collect(),
        )),
        PathAttribute::OnlyToCustomer(asn) => base.unknown_attrs.push((
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::ONLY_TO_CUSTOMER,
            asn.to_be_bytes().to_vec(),
        )),
        PathAttribute::Aggregator(aggregator) => {
            let flags = attr_flags::OPTIONAL
                | attr_flags::TRANSITIVE
                | if aggregator.partial {
                    attr_flags::PARTIAL
                } else {
                    0
                };
            let mut value = aggregator.asn.to_be_bytes().to_vec();
            value.extend_from_slice(&aggregator.router_id.octets());
            base.unknown_attrs
                .push((flags, attr_type::AGGREGATOR, value));
        }
        PathAttribute::MpReachNlri(mp) => *mp_reach = Some(mp),
        PathAttribute::MpUnreachNlri(mp) => *mp_unreach = Some(mp),
        PathAttribute::PmsiTunnel(_) => {
            return Err(
                "PMSI_TUNNEL attribute on a unicast Adj-RIB-Out route is not supported".to_string(),
            );
        }
        PathAttribute::Unknown(raw) => base.unknown_attrs.push((
            raw.flags & !attr_flags::EXTENDED_LENGTH,
            raw.type_code,
            raw.data.to_vec(),
        )),
        // `PathAttribute` is non-exhaustive: silently dropping an attribute
        // this build does not model would corrupt the comparison, so fail
        // the conversion instead.
        _ => {
            return Err("path attribute not modeled by this snapshot converter".to_string());
        }
    }
    Ok(())
}

/// Flatten AS_PATH segments into the snapshot's single ASN list
/// (documented consumer limitation shared with the from-mrt adapter:
/// segment structure is not compared).
fn flatten_as_path(path: &AsPath) -> Vec<u32> {
    use rustbgpd_wire::attribute::AsPathSegment;
    path.segments
        .iter()
        .flat_map(|segment| match segment {
            AsPathSegment::AsSequence(asns) | AsPathSegment::AsSet(asns) => asns.iter().copied(),
        })
        .collect()
}

/// Copy the shared attribute template for one NLRI entry.
fn clone_route(base: &SnapRoute, next_hop: Option<IpAddr>, path_id: Option<u32>) -> SnapRoute {
    SnapRoute {
        path_id,
        origin: base.origin,
        as_path: base.as_path.clone(),
        next_hop,
        med: base.med,
        local_pref: base.local_pref,
        communities: base.communities.clone(),
        extended_communities: base.extended_communities.clone(),
        large_communities: base.large_communities.clone(),
        unknown_attrs: base.unknown_attrs.clone(),
    }
}

/// Insert (or supersede — RFC 7854 §5: a later update for the same key
/// wins) one route under the hard bounds.
fn insert_route(
    state: &mut PeerState,
    total_routes: &mut usize,
    limits: Limits,
    key: RouteKey,
    route: SnapRoute,
) -> Result<(), String> {
    let (fam, addr, len, _) = key;
    state.expected.insert(fam);
    if !state.routes.contains_key(&key) {
        if *total_routes >= limits.max_routes {
            return Err(format!(
                "more than {} retained routes; refusing",
                limits.max_routes
            ));
        }
        let paths = state
            .routes
            .range((fam, addr, len, 0)..=(fam, addr, len, u32::MAX))
            .count();
        if paths >= limits.max_paths_per_nlri {
            return Err(format!(
                "more than {} paths for {addr}/{len}; refusing",
                limits.max_paths_per_nlri
            ));
        }
        *total_routes += 1;
    }
    state.routes.insert(key, route);
    Ok(())
}

/// Remove one route (a withdraw for an absent key is a legal no-op).
fn remove_route(
    state: &mut PeerState,
    total_routes: &mut usize,
    fam: Fam,
    addr: IpAddr,
    len: u8,
    path_id: u32,
) {
    state.expected.insert(fam);
    if state.routes.remove(&(fam, addr, len, path_id)).is_some() {
        *total_routes -= 1;
    }
}

#[cfg(test)]
pub(crate) mod test_fixture {
    //! Synthetic BMP capture builder. Messages are framed by the
    //! daemon's own RFC-pinned BMP encoder (`rustbgpd-bmp`), OPENs by
    //! the wire crate's encoder, and UPDATE bodies by hand — so the
    //! fixtures exercise the importer against independently golden-
    //! pinned wire bytes rather than its own encoding assumptions.

    use std::net::{IpAddr, Ipv4Addr};
    use std::time::UNIX_EPOCH;

    use rustbgpd_bmp::codec::{
        AfiStatCounter, StatCounter, encode_initiation, encode_peer_down, encode_peer_up,
        encode_route_monitoring, encode_stats_report, encode_termination,
    };
    use rustbgpd_bmp::types::{BmpPeerInfo, BmpPeerType, BmpVersion, PeerDownReason};
    use rustbgpd_wire::capability::{AddPathFamily, AddPathMode, Afi, Capability, Safi};
    use rustbgpd_wire::constants::attr_type;
    use rustbgpd_wire::open::OpenMessage;

    pub(crate) use super::super::ribsnap::test_fixture::as_path_attr;

    /// Encode one path attribute with its canonical RFC flags (the wire
    /// decoder validates flags per type, unlike the MRT fixture path).
    pub(crate) fn attr(type_code: u8, value: &[u8]) -> Vec<u8> {
        use rustbgpd_wire::constants::attr_flags::{OPTIONAL, TRANSITIVE};
        let flags = match type_code {
            attr_type::MULTI_EXIT_DISC | attr_type::MP_REACH_NLRI | attr_type::MP_UNREACH_NLRI => {
                OPTIONAL
            }
            attr_type::COMMUNITIES
            | attr_type::EXTENDED_COMMUNITIES
            | attr_type::LARGE_COMMUNITIES
            | attr_type::ONLY_TO_CUSTOMER
            | attr_type::AGGREGATOR
            | attr_type::AS4_PATH
            | attr_type::AS4_AGGREGATOR => OPTIONAL | TRANSITIVE,
            _ => TRANSITIVE,
        };
        let mut buf = vec![flags, type_code, u8::try_from(value.len()).unwrap()];
        buf.extend_from_slice(value);
        buf
    }

    /// Peer identity for the post-policy Adj-RIB-Out view (O=1, L=1).
    pub(crate) fn rib_out_info(addr: &str, asn: u32) -> BmpPeerInfo {
        let addr: IpAddr = addr.parse().unwrap();
        BmpPeerInfo {
            peer_addr: addr,
            peer_asn: asn,
            peer_bgp_id: Ipv4Addr::new(192, 0, 2, 99),
            peer_type: BmpPeerType::Global,
            is_ipv6: addr.is_ipv6(),
            is_post_policy: true,
            is_rib_out: true,
            is_as4: true,
            timestamp: UNIX_EPOCH,
        }
    }

    /// Full BGP OPEN PDU (with header) carrying the given capabilities.
    pub(crate) fn open_pdu(asn: u32, capabilities: Vec<Capability>) -> Vec<u8> {
        let open = OpenMessage {
            version: 4,
            my_as: u16::try_from(asn).unwrap_or(23456),
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 99),
            capabilities,
        };
        let mut buf = Vec::new();
        open.encode(&mut buf).unwrap();
        buf
    }

    pub(crate) fn mp(afi: Afi, safi: Safi) -> Capability {
        Capability::MultiProtocol { afi, safi }
    }

    pub(crate) fn add_path(afi: Afi, safi: Safi, send_receive: AddPathMode) -> Capability {
        Capability::AddPath(vec![AddPathFamily {
            afi,
            safi,
            send_receive,
        }])
    }

    /// Full BGP UPDATE PDU from raw body sections.
    pub(crate) fn update_pdu(withdrawn: &[u8], attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
        let total = 19 + 4 + withdrawn.len() + attrs.len() + nlri.len();
        let mut pdu = vec![0xFF; 16];
        pdu.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        pdu.push(2); // UPDATE
        pdu.extend_from_slice(&u16::try_from(withdrawn.len()).unwrap().to_be_bytes());
        pdu.extend_from_slice(withdrawn);
        pdu.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
        pdu.extend_from_slice(attrs);
        pdu.extend_from_slice(nlri);
        pdu
    }

    /// IPv4 NLRI bytes: optional Add-Path ID + length + prefix octets.
    pub(crate) fn v4_nlri(addr: [u8; 4], len: u8, path_id: Option<u32>) -> Vec<u8> {
        let mut nlri = Vec::new();
        if let Some(id) = path_id {
            nlri.extend_from_slice(&id.to_be_bytes());
        }
        nlri.push(len);
        nlri.extend_from_slice(&addr[..(usize::from(len)).div_ceil(8)]);
        nlri
    }

    /// MP_REACH_NLRI attribute for IPv6 unicast.
    pub(crate) fn mp_reach_v6_attr(next_hop: &str, nlri: &[u8]) -> Vec<u8> {
        let nh: std::net::Ipv6Addr = next_hop.parse().unwrap();
        let mut value = vec![0, 2, 1, 16];
        value.extend_from_slice(&nh.octets());
        value.push(0); // reserved
        value.extend_from_slice(nlri);
        attr(attr_type::MP_REACH_NLRI, &value)
    }

    /// IPv6 NLRI bytes (no Add-Path).
    pub(crate) fn v6_nlri(prefix: &str, len: u8) -> Vec<u8> {
        let addr: std::net::Ipv6Addr = prefix.parse().unwrap();
        let mut nlri = vec![len];
        nlri.extend_from_slice(&addr.octets()[..(usize::from(len)).div_ceil(8)]);
        nlri
    }

    /// IPv4-unicast End-of-RIB: the empty UPDATE (RFC 4724 §2).
    pub(crate) fn eor_v4() -> Vec<u8> {
        update_pdu(&[], &[], &[])
    }

    /// Family End-of-RIB: an UPDATE carrying only an empty
    /// MP_UNREACH_NLRI for the family.
    pub(crate) fn eor_mp(afi: u16, safi: u8) -> Vec<u8> {
        let mut value = afi.to_be_bytes().to_vec();
        value.push(safi);
        update_pdu(&[], &attr(attr_type::MP_UNREACH_NLRI, &value), &[])
    }

    /// MP_UNREACH_NLRI withdraw for IPv6 unicast.
    pub(crate) fn mp_unreach_v6(nlri: &[u8]) -> Vec<u8> {
        let mut value = 2u16.to_be_bytes().to_vec();
        value.push(1);
        value.extend_from_slice(nlri);
        attr(attr_type::MP_UNREACH_NLRI, &value)
    }

    pub(crate) fn initiation() -> Vec<u8> {
        encode_initiation("incumbent", "synthetic capture", BmpVersion::V3).to_vec()
    }

    pub(crate) fn peer_up(info: &BmpPeerInfo, sent_open: &[u8], received_open: &[u8]) -> Vec<u8> {
        encode_peer_up(
            info,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
            179,
            40000,
            sent_open,
            received_open,
            BmpVersion::V3,
        )
        .to_vec()
    }

    pub(crate) fn peer_down(info: &BmpPeerInfo) -> Vec<u8> {
        encode_peer_down(info, &PeerDownReason::RemoteNoNotification, BmpVersion::V3).to_vec()
    }

    pub(crate) fn route_monitoring(info: &BmpPeerInfo, pdu: &[u8]) -> Vec<u8> {
        encode_route_monitoring(info, pdu, None, BmpVersion::V3).to_vec()
    }

    /// RFC 8671 stats: type 15 total + type 17 per-family gauges.
    pub(crate) fn stats(info: &BmpPeerInfo, total: u64, per_family: &[(u16, u8, u64)]) -> Vec<u8> {
        let counters = vec![StatCounter {
            stat_type: 15,
            value: total,
        }];
        let afi_counters: Vec<AfiStatCounter> = per_family
            .iter()
            .map(|&(afi, safi, value)| AfiStatCounter {
                stat_type: 17,
                afi,
                safi,
                value,
            })
            .collect();
        encode_stats_report(info, &counters, &afi_counters, BmpVersion::V3).to_vec()
    }

    pub(crate) fn termination() -> Vec<u8> {
        encode_termination(0, "capture end", BmpVersion::V3).to_vec()
    }

    /// The golden multi-peer capture, built synthetically with the
    /// daemon's own BMP encoder (an M83 lab capture would carry
    /// rustbgpd's *own* view rather than an incumbent's, so a synthetic
    /// stream is both cheaper and the honest source here). Exercises:
    /// Initiation; Add-Path and plain peers; body and MP_REACH/UNREACH
    /// announce + withdraw; dump/live interleave supersede; End-of-RIB
    /// per family; post-EoR live update; matching RFC 8671 stats;
    /// typed-but-unsnapshotted (OTC) and fully unknown attributes;
    /// interleaved Adj-RIB-In messages; Termination.
    pub(crate) fn golden_capture() -> Vec<u8> {
        let peer_a = rib_out_info("192.0.2.1", 65001);
        let peer_b = rib_out_info("2001:db8::2", 65002);
        let mut capture = initiation();

        // Peer A: IPv4 unicast with Add-Path in effect (incumbent sends
        // Both, member receives Both) and 4-octet ASNs.
        let a_sent = open_pdu(
            65500,
            vec![
                mp(Afi::Ipv4, Safi::Unicast),
                add_path(Afi::Ipv4, Safi::Unicast, AddPathMode::Both),
                Capability::FourOctetAs { asn: 65500 },
            ],
        );
        let a_received = open_pdu(
            65001,
            vec![
                mp(Afi::Ipv4, Safi::Unicast),
                add_path(Afi::Ipv4, Safi::Unicast, AddPathMode::Both),
                Capability::FourOctetAs { asn: 65001 },
            ],
        );
        capture.extend(peer_up(&peer_a, &a_sent, &a_received));

        // Peer B: IPv4 + IPv6 unicast, no Add-Path.
        let b_sent = open_pdu(
            65500,
            vec![
                mp(Afi::Ipv4, Safi::Unicast),
                mp(Afi::Ipv6, Safi::Unicast),
                Capability::FourOctetAs { asn: 65500 },
            ],
        );
        let b_received = open_pdu(
            65002,
            vec![
                mp(Afi::Ipv4, Safi::Unicast),
                mp(Afi::Ipv6, Safi::Unicast),
                Capability::FourOctetAs { asn: 65002 },
            ],
        );
        capture.extend(peer_up(&peer_b, &b_sent, &b_received));

        // Peer A initial dump: 203.0.113.0/24 as two Add-Path paths.
        let mut attrs_1 = attr(attr_type::ORIGIN, &[0]);
        attrs_1.extend(as_path_attr(&[65500, 64999]));
        attrs_1.extend(attr(attr_type::NEXT_HOP, &[192, 0, 2, 254]));
        attrs_1.extend(attr(attr_type::MULTI_EXIT_DISC, &120u32.to_be_bytes()));
        attrs_1.extend(attr(
            attr_type::COMMUNITIES,
            &((65500u32 << 16) | 100).to_be_bytes(),
        ));
        capture.extend(route_monitoring(
            &peer_a,
            &update_pdu(&[], &attrs_1, &v4_nlri([203, 0, 113, 0], 24, Some(1))),
        ));
        let mut attrs_2 = attr(attr_type::ORIGIN, &[0]);
        attrs_2.extend(as_path_attr(&[65500, 64998]));
        attrs_2.extend(attr(attr_type::NEXT_HOP, &[192, 0, 2, 253]));
        capture.extend(route_monitoring(
            &peer_a,
            &update_pdu(&[], &attrs_2, &v4_nlri([203, 0, 113, 0], 24, Some(2))),
        ));

        // 198.51.100.0/24 announced then withdrawn before End-of-RIB —
        // must not appear in the snapshot.
        capture.extend(route_monitoring(
            &peer_a,
            &update_pdu(&[], &attrs_2, &v4_nlri([198, 51, 100, 0], 24, Some(1))),
        ));
        capture.extend(route_monitoring(
            &peer_a,
            &update_pdu(&v4_nlri([198, 51, 100, 0], 24, Some(1)), &[], &[]),
        ));

        // Dump/live interleave: path 1 re-announced with MED 121 before
        // End-of-RIB — the later update supersedes.
        let mut attrs_1b = attr(attr_type::ORIGIN, &[0]);
        attrs_1b.extend(as_path_attr(&[65500, 64999]));
        attrs_1b.extend(attr(attr_type::NEXT_HOP, &[192, 0, 2, 254]));
        attrs_1b.extend(attr(attr_type::MULTI_EXIT_DISC, &121u32.to_be_bytes()));
        attrs_1b.extend(attr(
            attr_type::COMMUNITIES,
            &((65500u32 << 16) | 100).to_be_bytes(),
        ));
        capture.extend(route_monitoring(
            &peer_a,
            &update_pdu(&[], &attrs_1b, &v4_nlri([203, 0, 113, 0], 24, Some(1))),
        ));

        // An interleaved pre-policy Adj-RIB-In message (O=0): skipped.
        let mut rib_in = rib_out_info("192.0.2.1", 65001);
        rib_in.is_rib_out = false;
        rib_in.is_post_policy = false;
        capture.extend(route_monitoring(
            &rib_in,
            &update_pdu(&[], &attrs_2, &v4_nlri([10, 99, 0, 0], 16, None)),
        ));

        capture.extend(route_monitoring(&peer_a, &eor_v4()));

        // Live update after End-of-RIB: OTC (typed, unsnapshotted) and a
        // fully unknown transitive attribute — both preserved.
        let mut attrs_live = attr(attr_type::ORIGIN, &[1]);
        attrs_live.extend(as_path_attr(&[65500]));
        attrs_live.extend(attr(attr_type::NEXT_HOP, &[192, 0, 2, 254]));
        attrs_live.extend(attr(attr_type::LOCAL_PREF, &200u32.to_be_bytes()));
        attrs_live.extend(attr(
            attr_type::EXTENDED_COMMUNITIES,
            &0x0002_FFDC_0000_0064_u64.to_be_bytes(),
        ));
        let mut large = 65500u32.to_be_bytes().to_vec();
        large.extend(7u32.to_be_bytes());
        large.extend(9u32.to_be_bytes());
        attrs_live.extend(attr(attr_type::LARGE_COMMUNITIES, &large));
        attrs_live.extend(attr(attr_type::ONLY_TO_CUSTOMER, &65500u32.to_be_bytes()));
        let mut unknown = vec![0xC0, 200, 4];
        unknown.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        attrs_live.extend(unknown);
        capture.extend(route_monitoring(
            &peer_a,
            &update_pdu(&[], &attrs_live, &v4_nlri([100, 64, 0, 0], 24, Some(1))),
        ));

        // Post-EoR RFC 8671 stats matching the folded state: peer A
        // holds 3 v4 routes.
        capture.extend(stats(&peer_a, 3, &[(1, 1, 3)]));

        // Peer B: one v4 body route, one v6 MP route (announced twice —
        // second announcement supersedes with a different MED), one v6
        // route withdrawn via MP_UNREACH.
        let mut b_v4 = attr(attr_type::ORIGIN, &[0]);
        b_v4.extend(as_path_attr(&[65500, 64997]));
        b_v4.extend(attr(attr_type::NEXT_HOP, &[192, 0, 2, 254]));
        capture.extend(route_monitoring(
            &peer_b,
            &update_pdu(&[], &b_v4, &v4_nlri([100, 65, 0, 0], 24, None)),
        ));
        let mut b_v6 = attr(attr_type::ORIGIN, &[0]);
        b_v6.extend(as_path_attr(&[65500, 64997]));
        b_v6.extend(attr(attr_type::MULTI_EXIT_DISC, &50u32.to_be_bytes()));
        b_v6.extend(mp_reach_v6_attr(
            "2001:db8::1",
            &v6_nlri("2001:db8:100::", 48),
        ));
        capture.extend(route_monitoring(&peer_b, &update_pdu(&[], &b_v6, &[])));
        let mut b_v6b = attr(attr_type::ORIGIN, &[0]);
        b_v6b.extend(as_path_attr(&[65500, 64997]));
        b_v6b.extend(attr(attr_type::MULTI_EXIT_DISC, &51u32.to_be_bytes()));
        b_v6b.extend(mp_reach_v6_attr(
            "2001:db8::1",
            &v6_nlri("2001:db8:100::", 48),
        ));
        capture.extend(route_monitoring(&peer_b, &update_pdu(&[], &b_v6b, &[])));
        let mut b_v6_gone = attr(attr_type::ORIGIN, &[0]);
        b_v6_gone.extend(as_path_attr(&[65500, 64997]));
        b_v6_gone.extend(mp_reach_v6_attr(
            "2001:db8::1",
            &v6_nlri("2001:db8:200::", 48),
        ));
        capture.extend(route_monitoring(&peer_b, &update_pdu(&[], &b_v6_gone, &[])));
        capture.extend(route_monitoring(
            &peer_b,
            &update_pdu(&[], &mp_unreach_v6(&v6_nlri("2001:db8:200::", 48)), &[]),
        ));
        capture.extend(route_monitoring(&peer_b, &eor_v4()));
        capture.extend(route_monitoring(&peer_b, &eor_mp(2, 1)));
        capture.extend(stats(&peer_b, 2, &[(1, 1, 1), (2, 1, 1)]));

        capture.extend(termination());
        capture
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixture::*;
    use super::*;
    use rustbgpd_wire::capability::AddPathMode as Mode;
    use std::io::Write;

    fn write_capture(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        file.flush().unwrap();
        file
    }

    fn opts<'a>(file: &'a Path, peers: &'a [String]) -> FromBmpOpts<'a> {
        FromBmpOpts {
            file,
            peers,
            source: Some("synthetic-lab"),
            generation: 3,
        }
    }

    fn run_capture(bytes: &[u8]) -> Result<(String, Vec<String>), String> {
        let file = write_capture(bytes);
        run(&opts(file.path(), &[]))
    }

    /// Standard single-peer prologue: Initiation + a plain v4-only peer.
    fn v4_peer_capture() -> (Vec<u8>, rustbgpd_bmp::types::BmpPeerInfo) {
        let info = rib_out_info("192.0.2.1", 65001);
        let open = open_pdu(65500, vec![mp(Afi::Ipv4, Safi::Unicast)]);
        let peer_open = open_pdu(65001, vec![mp(Afi::Ipv4, Safi::Unicast)]);
        let mut capture = initiation();
        capture.extend(peer_up(&info, &open, &peer_open));
        (capture, info)
    }

    fn simple_announce(prefix: [u8; 4], len: u8) -> Vec<u8> {
        let mut attrs = attr(rustbgpd_wire::constants::attr_type::ORIGIN, &[0]);
        attrs.extend(as_path_attr(&[65500]));
        attrs.extend(attr(
            rustbgpd_wire::constants::attr_type::NEXT_HOP,
            &[192, 0, 2, 254],
        ));
        update_pdu(&[], &attrs, &v4_nlri(prefix, len, None))
    }

    #[test]
    fn emits_golden_snapshot() {
        let (snapshot, notes) = run_capture(&golden_capture()).unwrap();
        let golden_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ribsnap/from-bmp.expected.ndjson"
        );
        // BLESS=1 rewrites the golden (fixture refresh; review the diff).
        if std::env::var_os("BLESS").is_some() {
            std::fs::write(golden_path, &snapshot).unwrap();
        }
        let golden = std::fs::read_to_string(golden_path).unwrap();
        assert_eq!(snapshot, golden);
        // The withdrawn routes never appear.
        assert!(!snapshot.contains("198.51.100.0"));
        assert!(!snapshot.contains("2001:db8:200::"));
        // The rib-in prefix never appears.
        assert!(!snapshot.contains("10.99.0.0"));
        // The interleaved dump/live update superseded (MED 121, not 120).
        assert!(snapshot.contains("\"med\":121"));
        assert!(!snapshot.contains("\"med\":120"));
        // Second announcement of the same v6 NLRI superseded.
        assert!(snapshot.contains("\"med\":51"));
        assert!(!snapshot.contains("\"med\":50"));
        // OTC and the raw unknown attribute are preserved byte-exact.
        assert!(snapshot.contains(r#"{"flags":192,"type_code":35,"value":"0000ffdc"}"#));
        assert!(snapshot.contains(r#"{"flags":192,"type_code":200,"value":"deadbeef"}"#));
        // Add-Path IDs surface as diagnostics-only path_id.
        assert!(snapshot.contains("\"path_id\":1"));
        assert!(snapshot.contains("\"path_id\":2"));
        // The skipped rib-in message is noted.
        assert!(notes.iter().any(|n| n.contains("Adj-RIB-In")), "{notes:?}");
    }

    #[test]
    fn pre_policy_adj_rib_out_is_refused() {
        let (mut capture, mut info) = v4_peer_capture();
        info.is_post_policy = false; // O=1, L=0
        capture.extend(route_monitoring(&info, &simple_announce([10, 0, 0, 0], 24)));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("pre-policy Adj-RIB-Out"), "{err}");
        assert!(err.contains("not comparable"), "{err}");
    }

    #[test]
    fn missing_end_of_rib_is_refused() {
        // v4 announce but no EoR at all.
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &simple_announce([10, 0, 0, 0], 24)));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("End-of-RIB not seen"), "{err}");
        assert!(err.contains("incomplete"), "{err}");

        // Negotiated v6 without a v6 EoR is incomplete even when v4
        // completed.
        let info = rib_out_info("192.0.2.1", 65001);
        let caps = || vec![mp(Afi::Ipv4, Safi::Unicast), mp(Afi::Ipv6, Safi::Unicast)];
        let mut capture = initiation();
        capture.extend(peer_up(
            &info,
            &open_pdu(65500, caps()),
            &open_pdu(65001, caps()),
        ));
        capture.extend(route_monitoring(&info, &eor_v4()));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("ipv6_unicast"), "{err}");
        assert!(err.contains("End-of-RIB not seen"), "{err}");

        // --peer can exclude the incomplete peer.
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &simple_announce([10, 0, 0, 0], 24)));
        capture.extend(route_monitoring(&info, &eor_v4()));
        let incomplete = rib_out_info("192.0.2.7", 65007);
        let open = open_pdu(65500, vec![mp(Afi::Ipv4, Safi::Unicast)]);
        let peer_open = open_pdu(65007, vec![mp(Afi::Ipv4, Safi::Unicast)]);
        capture.extend(peer_up(&incomplete, &open, &peer_open));
        capture.extend(route_monitoring(
            &incomplete,
            &simple_announce([10, 7, 0, 0], 24),
        ));
        let file = write_capture(&capture);
        let err = run(&opts(file.path(), &[])).unwrap_err();
        assert!(err.contains("192.0.2.7"), "{err}");
        let filter = vec!["192.0.2.1".to_string()];
        let (snapshot, _) = run(&opts(file.path(), &filter)).unwrap();
        assert!(snapshot.contains("10.0.0.0/24"));
        assert!(!snapshot.contains("10.7.0.0/24"));
    }

    #[test]
    fn reconnect_invalidates_previous_generation() {
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &simple_announce([10, 1, 0, 0], 24)));
        capture.extend(route_monitoring(&info, &eor_v4()));
        // Reconnect: new Initiation, fresh Peer Up, different route.
        let (second, info) = v4_peer_capture();
        capture.extend(second);
        capture.extend(route_monitoring(&info, &simple_announce([10, 2, 0, 0], 24)));
        capture.extend(route_monitoring(&info, &eor_v4()));
        let (snapshot, _) = run_capture(&capture).unwrap();
        assert!(!snapshot.contains("10.1.0.0/24"), "old generation leaked");
        assert!(snapshot.contains("10.2.0.0/24"));

        // A pre-reconnect EoR must not satisfy the new generation.
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &eor_v4()));
        let (second, info) = v4_peer_capture();
        capture.extend(second);
        capture.extend(route_monitoring(&info, &simple_announce([10, 3, 0, 0], 24)));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("End-of-RIB not seen"), "{err}");
    }

    #[test]
    fn peer_down_invalidates_peer_state() {
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &simple_announce([10, 1, 0, 0], 24)));
        capture.extend(route_monitoring(&info, &eor_v4()));
        capture.extend(peer_down(&info));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("no global-instance peers"), "{err}");

        // Down then re-up requires a fresh dump: the old EoR is gone.
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &eor_v4()));
        capture.extend(peer_down(&info));
        let open = open_pdu(65500, vec![mp(Afi::Ipv4, Safi::Unicast)]);
        let peer_open = open_pdu(65001, vec![mp(Afi::Ipv4, Safi::Unicast)]);
        capture.extend(peer_up(&info, &open, &peer_open));
        capture.extend(route_monitoring(&info, &simple_announce([10, 4, 0, 0], 24)));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("End-of-RIB not seen"), "{err}");
    }

    #[test]
    fn out_of_protocol_sequences_are_refused() {
        // Route Monitoring before Initiation.
        let info = rib_out_info("192.0.2.1", 65001);
        let capture = route_monitoring(&info, &simple_announce([10, 0, 0, 0], 24));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("before the Initiation"), "{err}");

        // Route Monitoring without a Peer Up.
        let mut capture = initiation();
        capture.extend(route_monitoring(&info, &simple_announce([10, 0, 0, 0], 24)));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("without a Peer Up"), "{err}");

        // Peer Down without a Peer Up.
        let mut capture = initiation();
        capture.extend(peer_down(&info));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("Peer Down for peer"), "{err}");

        // Message after Termination without a new Initiation.
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &eor_v4()));
        capture.extend(termination());
        capture.extend(route_monitoring(&info, &eor_v4()));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("after a Termination"), "{err}");

        // ASN conflict between Peer Up and a later per-peer header.
        let (mut capture, _) = v4_peer_capture();
        let liar = rib_out_info("192.0.2.1", 64999);
        capture.extend(route_monitoring(&liar, &simple_announce([10, 0, 0, 0], 24)));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("conflicts with the Peer Up ASN"), "{err}");
    }

    #[test]
    fn malformed_and_truncated_input_is_refused() {
        // Empty file: no Initiation.
        let err = run_capture(&[]).unwrap_err();
        assert!(err.contains("no BMP Initiation"), "{err}");

        // Truncated mid-message.
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &eor_v4()));
        capture.truncate(capture.len() - 3);
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("truncated"), "{err}");

        // Wrong version byte (a BMPv4 or non-BMP stream).
        let mut capture = initiation();
        capture[0] = 4;
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("version 4"), "{err}");

        // Unknown message type.
        let mut capture = initiation();
        let mut bogus = initiation();
        bogus[5] = 99;
        capture.extend(bogus);
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("unknown BMP message type 99"), "{err}");

        // Corrupt embedded UPDATE (bad marker).
        let (mut capture, info) = v4_peer_capture();
        let mut pdu = simple_announce([10, 0, 0, 0], 24);
        pdu[0] = 0x00;
        capture.extend(route_monitoring(&info, &pdu));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("BMP message #3"), "{err}");

        // Non-UPDATE PDU inside Route Monitoring.
        let (mut capture, info) = v4_peer_capture();
        let open = open_pdu(65500, vec![]);
        capture.extend(route_monitoring(&info, &open));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("expected UPDATE"), "{err}");

        // Trailing bytes after the declared PDU length.
        let (mut capture, info) = v4_peer_capture();
        let mut pdu = eor_v4();
        pdu.push(0);
        capture.extend(route_monitoring(&info, &pdu));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("framing is corrupt"), "{err}");
    }

    /// RFC 7911 directionality: path IDs are present only when the
    /// incumbent advertised *send* and the member advertised *receive*.
    /// A receive-only incumbent mode must not switch the decoder into
    /// Add-Path framing.
    #[test]
    fn add_path_requires_send_and_receive_directions() {
        let info = rib_out_info("192.0.2.1", 65001);
        let sent = open_pdu(
            65500,
            vec![
                mp(Afi::Ipv4, Safi::Unicast),
                add_path(Afi::Ipv4, Safi::Unicast, Mode::Receive),
            ],
        );
        let received = open_pdu(
            65001,
            vec![
                mp(Afi::Ipv4, Safi::Unicast),
                add_path(Afi::Ipv4, Safi::Unicast, Mode::Both),
            ],
        );
        let mut capture = initiation();
        capture.extend(peer_up(&info, &sent, &received));
        // Plain (non-Add-Path) NLRI must parse; path_id never emitted.
        capture.extend(route_monitoring(&info, &simple_announce([10, 0, 0, 0], 24)));
        capture.extend(route_monitoring(&info, &eor_v4()));
        let (snapshot, _) = run_capture(&capture).unwrap();
        assert!(snapshot.contains("10.0.0.0/24"));
        assert!(!snapshot.contains("path_id"));
    }

    /// The per-peer header A flag switches AS_PATH decoding to legacy
    /// 2-octet ASNs (RFC 7854 §4.2).
    #[test]
    fn legacy_two_octet_as_path_parses_via_a_flag() {
        let mut info = rib_out_info("192.0.2.1", 65001);
        info.is_as4 = false;
        let open = open_pdu(65500, vec![mp(Afi::Ipv4, Safi::Unicast)]);
        let peer_open = open_pdu(65001, vec![mp(Afi::Ipv4, Safi::Unicast)]);
        let mut capture = initiation();
        capture.extend(peer_up(&info, &open, &peer_open));
        // AS_SEQUENCE of two 2-octet ASNs.
        let mut attrs = attr(rustbgpd_wire::constants::attr_type::ORIGIN, &[0]);
        let mut as_path = vec![2, 2];
        as_path.extend(65500u16.to_be_bytes());
        as_path.extend(64999u16.to_be_bytes());
        attrs.extend(attr(rustbgpd_wire::constants::attr_type::AS_PATH, &as_path));
        attrs.extend(attr(
            rustbgpd_wire::constants::attr_type::NEXT_HOP,
            &[192, 0, 2, 254],
        ));
        capture.extend(route_monitoring(
            &info,
            &update_pdu(&[], &attrs, &v4_nlri([10, 0, 0, 0], 24, None)),
        ));
        capture.extend(route_monitoring(&info, &eor_v4()));
        let (snapshot, _) = run_capture(&capture).unwrap();
        assert!(snapshot.contains("\"as_path\":[65500,64999]"), "{snapshot}");
    }

    /// Load-bearing RFC 6793 adapter proof: removing legacy AS4 reconstruction
    /// leaves `AS_TRANS` in `as_path`, and dropping the typed AGGREGATOR arm
    /// either refuses conversion or loses the canonical type-7 record. Keeping
    /// compatibility types 17/18 also fails the exact unknown-attribute list.
    #[test]
    fn legacy_as4_path_and_aggregator_reconstruct_to_canonical_snapshot() {
        let mut info = rib_out_info("192.0.2.1", 65001);
        info.is_as4 = false;
        let open = open_pdu(65500, vec![mp(Afi::Ipv4, Safi::Unicast)]);
        let peer_open = open_pdu(65001, vec![mp(Afi::Ipv4, Safi::Unicast)]);
        let mut capture = initiation();
        capture.extend(peer_up(&info, &open, &peer_open));

        let mut attrs = attr(attr_type::ORIGIN, &[0]);
        let mut legacy_path = vec![2, 2];
        legacy_path.extend(65000u16.to_be_bytes());
        legacy_path.extend(23456u16.to_be_bytes());
        attrs.extend(attr(attr_type::AS_PATH, &legacy_path));
        let mut as4_path = vec![2, 2];
        as4_path.extend(65000u32.to_be_bytes());
        as4_path.extend(4_200_000_001u32.to_be_bytes());
        attrs.extend(attr(attr_type::AS4_PATH, &as4_path));
        attrs.extend(attr(attr_type::NEXT_HOP, &[192, 0, 2, 254]));

        let router_id = Ipv4Addr::new(192, 0, 2, 9);
        let mut legacy_aggregator = 23456u16.to_be_bytes().to_vec();
        legacy_aggregator.extend_from_slice(&router_id.octets());
        attrs.extend(attr(attr_type::AGGREGATOR, &legacy_aggregator));
        let mut as4_aggregator = 4_200_000_001u32.to_be_bytes().to_vec();
        as4_aggregator.extend_from_slice(&router_id.octets());
        let mut encoded_as4_aggregator = attr(attr_type::AS4_AGGREGATOR, &as4_aggregator);
        encoded_as4_aggregator[0] |= rustbgpd_wire::constants::attr_flags::PARTIAL;
        attrs.extend(encoded_as4_aggregator);

        capture.extend(route_monitoring(
            &info,
            &update_pdu(&[], &attrs, &v4_nlri([10, 0, 0, 0], 24, None)),
        ));
        capture.extend(route_monitoring(&info, &eor_v4()));

        let (snapshot, _) = run_capture(&capture).unwrap();
        let route: serde_json::Value = serde_json::from_str(
            snapshot
                .lines()
                .find(|line| line.contains("\"record\":\"route\""))
                .expect("one route record"),
        )
        .unwrap();
        assert_eq!(
            route["as_path"],
            serde_json::json!([65000, 4_200_000_001u32])
        );
        assert_eq!(
            route["unknown_attrs"],
            serde_json::json!([{
                "flags": 224,
                "type_code": attr_type::AGGREGATOR,
                "value": "fa56ea01c0000209"
            }])
        );
    }

    #[test]
    fn stats_mismatch_after_end_of_rib_is_refused() {
        // Total gauge (type 15) mismatch.
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &simple_announce([10, 0, 0, 0], 24)));
        capture.extend(route_monitoring(&info, &eor_v4()));
        capture.extend(stats(&info, 2, &[(1, 1, 1)])); // folded state holds 1
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("stat 15"), "{err}");
        assert!(err.contains("reports 2"), "{err}");

        // Per-family gauge (type 17) mismatch.
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &simple_announce([10, 0, 0, 0], 24)));
        capture.extend(route_monitoring(&info, &eor_v4()));
        capture.extend(stats(&info, 1, &[(1, 1, 2)]));
        let err = run_capture(&capture).unwrap_err();
        assert!(err.contains("stat 17"), "{err}");
        assert!(err.contains("reports 2"), "{err}");

        // Matching stats pass (and completeness never required them —
        // the golden capture also proves the no-stats path completes).
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &simple_announce([10, 0, 0, 0], 24)));
        capture.extend(route_monitoring(&info, &eor_v4()));
        capture.extend(stats(&info, 1, &[(1, 1, 1)]));
        assert!(run_capture(&capture).is_ok());

        // Pre-EoR stats are not cross-checked (dump still in flight).
        let (mut capture, info) = v4_peer_capture();
        capture.extend(stats(&info, 99, &[(1, 1, 99)]));
        capture.extend(route_monitoring(&info, &simple_announce([10, 0, 0, 0], 24)));
        capture.extend(route_monitoring(&info, &eor_v4()));
        assert!(run_capture(&capture).is_ok());
    }

    #[test]
    fn instance_peers_are_skipped_with_a_note() {
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &simple_announce([10, 0, 0, 0], 24)));
        capture.extend(route_monitoring(&info, &eor_v4()));
        let mut rd_peer = rib_out_info("192.0.2.200", 65200);
        rd_peer.peer_type = rustbgpd_bmp::types::BmpPeerType::RdInstance;
        let open = open_pdu(65500, vec![]);
        capture.extend(peer_up(&rd_peer, &open, &open));
        capture.extend(route_monitoring(
            &rd_peer,
            &simple_announce([10, 200, 0, 0], 24),
        ));
        let (snapshot, notes) = run_capture(&capture).unwrap();
        assert!(!snapshot.contains("10.200.0.0"));
        assert!(
            notes
                .iter()
                .any(|n| n.contains("instance peer 192.0.2.200")),
            "{notes:?}"
        );
    }

    #[test]
    fn hard_bounds_are_enforced() {
        let tiny = Limits {
            max_routes: 2,
            ..Limits::default()
        };
        let (mut capture, info) = v4_peer_capture();
        for i in 0..3u8 {
            capture.extend(route_monitoring(&info, &simple_announce([10, i, 0, 0], 24)));
        }
        capture.extend(route_monitoring(&info, &eor_v4()));
        let file = write_capture(&capture);
        let err = run_with_limits(&opts(file.path(), &[]), tiny).unwrap_err();
        assert!(err.contains("more than 2 retained routes"), "{err}");

        // Paths-per-NLRI bound: many Add-Path IDs for one prefix.
        let tiny = Limits {
            max_paths_per_nlri: 2,
            ..Limits::default()
        };
        let info = rib_out_info("192.0.2.1", 65001);
        let caps = |asn| {
            open_pdu(
                asn,
                vec![
                    mp(Afi::Ipv4, Safi::Unicast),
                    add_path(Afi::Ipv4, Safi::Unicast, Mode::Both),
                ],
            )
        };
        let mut capture = initiation();
        capture.extend(peer_up(&info, &caps(65500), &caps(65001)));
        for id in 1..=3u32 {
            let mut attrs = attr(rustbgpd_wire::constants::attr_type::ORIGIN, &[0]);
            attrs.extend(as_path_attr(&[65500]));
            attrs.extend(attr(
                rustbgpd_wire::constants::attr_type::NEXT_HOP,
                &[192, 0, 2, 254],
            ));
            capture.extend(route_monitoring(
                &info,
                &update_pdu(&[], &attrs, &v4_nlri([10, 0, 0, 0], 24, Some(id))),
            ));
        }
        let file = write_capture(&capture);
        let err = run_with_limits(&opts(file.path(), &[]), tiny).unwrap_err();
        assert!(err.contains("more than 2 paths"), "{err}");

        // Oversized BMP message length field.
        let tiny = Limits {
            max_bmp_message_len: 64,
            ..Limits::default()
        };
        let (capture, _) = v4_peer_capture();
        let file = write_capture(&capture);
        let err = run_with_limits(&opts(file.path(), &[]), tiny).unwrap_err();
        assert!(err.contains("exceeds the 64 byte limit"), "{err}");
    }

    #[test]
    fn peer_filter_missing_peer_is_refused() {
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &eor_v4()));
        let file = write_capture(&capture);
        let filter = vec!["192.0.2.99".to_string()];
        let err = run(&opts(file.path(), &filter)).unwrap_err();
        assert!(err.contains("192.0.2.99"), "{err}");
        assert!(err.contains("no state"), "{err}");

        let bad = vec!["not-an-ip".to_string()];
        let err = run(&opts(file.path(), &bad)).unwrap_err();
        assert!(err.contains("invalid --peer"), "{err}");
    }

    /// The public entry point maps refusal to exit 2 with no stdout.
    #[test]
    fn refusal_exit_code_contract() {
        let (capture, _) = v4_peer_capture(); // no EoR: incomplete
        let file = write_capture(&capture);
        assert_eq!(from_bmp(&opts(file.path(), &[])), EXIT_REFUSED);
        let (mut capture, info) = v4_peer_capture();
        capture.extend(route_monitoring(&info, &eor_v4()));
        let file = write_capture(&capture);
        assert_eq!(from_bmp(&opts(file.path(), &[])), EXIT_OK);
    }
}
