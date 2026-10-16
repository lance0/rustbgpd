//! Real-daemon recovery qualification. Python owns triggers and the frozen campaign.

use super::*;
use rustbgpd_wire::{MplsLabelEntry, RouteDistinguisher, VpnNlri, VpnNlriEntry, VpnPrefix};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::oneshot;

const LOCAL_AS: u32 = 64512;
const ORIGIN_BASE: u32 = 4_200_100_000;
const RECEIVER_BUFFER: usize = 4096;
const DENIED: usize = 4;
const RDS: [RouteDistinguisher; 2] = [
    RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
    RouteDistinguisher([0, 2, 0, 0, 0xfd, 0xe8, 0, 100]),
];
const CELL_DEADLINE: Duration = Duration::from_secs(1800);
/// `/readyz` cadence (4 Hz) and per-request bound. Every sample is recorded;
/// the controller judges ceilings, so a slow or failed sample never aborts.
const READINESS_INTERVAL: Duration = Duration::from_millis(250);
const READINESS_REQUEST_DEADLINE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
struct Shape {
    vpn: bool,
    counts: [usize; 2],
    denied: usize,
    batch_size: usize,
}

impl Shape {
    fn new(profile: &str, pressure: bool) -> Result<Self, String> {
        Ok(Self {
            vpn: match profile {
                "full-uc" => false,
                "full-vpn" => true,
                _ => return Err("profile must be full-uc or full-vpn".into()),
            },
            counts: [1_000_000, 230_000],
            denied: if pressure { DENIED } else { 0 },
            batch_size: 80,
        })
    }

    fn families(self) -> [(Afi, Safi); 2] {
        let safi = if self.vpn {
            Safi::MplsVpn
        } else {
            Safi::Unicast
        };
        [(Afi::Ipv4, safi), (Afi::Ipv6, safi)]
    }

    fn chunks(self) -> usize {
        self.counts
            .map(|count| count.div_ceil(self.batch_size))
            .iter()
            .sum()
    }

    fn origin(self, family: usize, index: usize, generation_b: bool) -> u32 {
        let chunk = if family == 0 {
            0
        } else {
            self.counts[0].div_ceil(self.batch_size)
        } + index / self.batch_size;
        ORIGIN_BASE + 2 * u32::try_from(chunk).unwrap() + u32::from(generation_b)
    }

    fn prefix(self, family: usize, index: usize) -> Prefix {
        let index = u32::try_from(if self.vpn { index / 2 } else { index }).unwrap();
        if family == 0 {
            Prefix::V4(base_prefix(index))
        } else {
            Prefix::V6(base_prefix6(index))
        }
    }

    fn index(
        self,
        prefix: Prefix,
        rd: Option<RouteDistinguisher>,
    ) -> Result<(usize, usize), String> {
        let (family, inner) = match prefix {
            Prefix::V4(p) => (
                0,
                base_prefix_index(p, u32::try_from(self.counts[0]).unwrap()),
            ),
            Prefix::V6(p) => (
                1,
                base_prefix6_index(p, u32::try_from(self.counts[1]).unwrap()),
            ),
        };
        let inner = inner.ok_or("unknown or noncanonical prefix")?;
        let index = if self.vpn {
            let rd = RDS
                .iter()
                .position(|value| Some(*value) == rd)
                .ok_or("unknown raw RD")?;
            inner
                .checked_mul(2)
                .and_then(|value| value.checked_add(rd))
                .ok_or("index overflow")?
        } else {
            if rd.is_some() {
                return Err("RD on unicast route".into());
            }
            inner
        };
        if index >= self.counts[family] {
            return Err("route outside finite fixture".into());
        }
        Ok((family, index))
    }

    fn vpn(self, family: usize, index: usize) -> VpnNlri {
        let prefix = match self.prefix(family, index) {
            Prefix::V4(p) => VpnPrefix::v4(p.addr, p.len).unwrap(),
            Prefix::V6(p) => VpnPrefix::v6(p.addr, p.len).unwrap(),
        };
        VpnNlri {
            labels: vec![MplsLabelEntry::try_new(
                16_000 + u32::try_from(index % 1_000_000).unwrap(),
                0,
                true,
            )
            .unwrap()],
            route_distinguisher: RDS[index % 2],
            prefix,
        }
    }
}

fn next_hop(family: usize) -> IpAddr {
    if family == 0 {
        IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1))
    } else {
        IpAddr::V6(Ipv6Addr::new(0xfd09, 0, 0, 0, 0, 0, 0, 1))
    }
}

fn attributes(origin: u32) -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![origin])],
        }),
        PathAttribute::LocalPref(100),
    ]
}

fn announce(
    shape: Shape,
    family: usize,
    start: usize,
    end: usize,
    generation_b: bool,
) -> Result<Message, String> {
    if start >= end
        || end > shape.counts[family]
        || start / shape.batch_size != (end - 1) / shape.batch_size
    {
        return Err("announcement crosses its finite origin chunk".into());
    }
    let mut attrs = attributes(shape.origin(family, start, generation_b));
    if !shape.vpn && family == 0 {
        attrs.push(PathAttribute::NextHop(Ipv4Addr::new(10, 9, 0, 1)));
        let entries = (start..end)
            .map(|index| Ipv4NlriEntry {
                path_id: 0,
                prefix: match shape.prefix(family, index) {
                    Prefix::V4(p) => p,
                    Prefix::V6(_) => unreachable!(),
                },
            })
            .collect::<Vec<_>>();
        return UpdateMessage::try_build(&entries, &[], &attrs, true, false, Ipv4UnicastMode::Body)
            .map(Message::Update)
            .map_err(|error| error.to_string());
    }
    let mut mp = MpReachNlri {
        afi: if family == 0 { Afi::Ipv4 } else { Afi::Ipv6 },
        safi: if shape.vpn {
            Safi::MplsVpn
        } else {
            Safi::Unicast
        },
        next_hop: next_hop(family),
        link_local_next_hop: None,
        announced: Vec::new(),
        flowspec_announced: Vec::new(),
        evpn_announced: Vec::new(),
        bgpls_announced: Vec::new(),
        labeled_announced: Vec::new(),
        vpn_announced: Vec::new(),
        rtc_announced: Vec::new(),
    };
    if shape.vpn {
        mp.vpn_announced = (start..end)
            .map(|index| VpnNlriEntry {
                path_id: 0,
                nlri: shape.vpn(family, index),
            })
            .collect();
    } else {
        mp.announced = (start..end)
            .map(|index| NlriEntry {
                path_id: 0,
                prefix: shape.prefix(family, index),
            })
            .collect();
    }
    attrs.push(PathAttribute::MpReachNlri(Box::new(mp)));
    UpdateMessage::try_build(&[], &[], &attrs, true, false, Ipv4UnicastMode::Body)
        .map(Message::Update)
        .map_err(|error| error.to_string())
}

fn end_of_rib(shape: Shape, family: usize) -> Result<Message, String> {
    let attributes = if !shape.vpn && family == 0 {
        Vec::new()
    } else {
        let (afi, safi) = shape.families()[family];
        vec![PathAttribute::MpUnreachNlri(Box::new(MpUnreachNlri {
            afi,
            safi,
            withdrawn: Vec::new(),
            flowspec_withdrawn: Vec::new(),
            evpn_withdrawn: Vec::new(),
            bgpls_withdrawn: Vec::new(),
            vpn_withdrawn: Vec::new(),
            labeled_withdrawn: Vec::new(),
            rtc_withdrawn: Vec::new(),
        }))]
    };
    UpdateMessage::try_build(&[], &[], &attributes, true, false, Ipv4UnicastMode::Body)
        .map(Message::Update)
        .map_err(|error| error.to_string())
}

type SourceWrite = (Message, Option<oneshot::Sender<Result<(), String>>>);

async fn feed_generation(
    sender: &mpsc::Sender<SourceWrite>,
    shape: Shape,
    generation_b: bool,
    churn: bool,
) -> Result<(), String> {
    let (drained, receipt) = oneshot::channel();
    let mut drained = Some(drained);
    for family in 0..2 {
        for start in (0..shape.counts[family]).step_by(shape.batch_size) {
            let end = (start + shape.batch_size).min(shape.counts[family]);
            sender
                .send((announce(shape, family, start, end, generation_b)?, None))
                .await
                .map_err(|_| "source writer ended")?;
            if churn {
                let last = family == 1 && end == shape.counts[family];
                sender
                    .send((
                        end_of_rib(shape, family)?,
                        if last { drained.take() } else { None },
                    ))
                    .await
                    .map_err(|_| "source writer ended")?;
            }
        }
        if !churn {
            sender
                .send((
                    end_of_rib(shape, family)?,
                    if family == 1 { drained.take() } else { None },
                ))
                .await
                .map_err(|_| "source writer ended")?;
        }
    }
    tokio::time::timeout(CELL_DEADLINE, receipt)
        .await
        .map_err(|_| "fixed source-drain deadline expired")?
        .map_err(|_| "source writer ended before drain")??;
    Ok(())
}

struct Inventory {
    shape: Shape,
    present: [Vec<u64>; 2],
    generation: [Vec<u64>; 2],
    withdrawn: [Vec<u64>; 2],
    target_b: bool,
    recovering: bool,
    announces: [u64; 2],
    withdraws: [u64; 2],
    present_count: [usize; 2],
    generation_count: [usize; 2],
    withdrawn_count: [usize; 2],
    started: Option<Instant>,
    completion_seconds: Option<f64>,
    error: Option<String>,
}

impl Inventory {
    fn new(shape: Shape) -> Self {
        let words = || shape.counts.map(|count| vec![0; count.div_ceil(64)]);
        Self {
            shape,
            present: words(),
            generation: words(),
            withdrawn: words(),
            target_b: false,
            recovering: false,
            announces: [0; 2],
            withdraws: [0; 2],
            present_count: [0; 2],
            generation_count: [0; 2],
            withdrawn_count: [0; 2],
            started: None,
            completion_seconds: None,
            error: None,
        }
    }

    fn arm(&mut self, target_b: bool) {
        self.target_b = target_b;
        self.recovering = true;
        self.generation_count = [0; 2];
        self.withdrawn_count = [0; 2];
        self.completion_seconds = None;
        for family in 0..2 {
            self.generation[family].fill(0);
            self.withdrawn[family].fill(0);
        }
    }

    fn event(&mut self, family: usize, index: usize, marker: Option<u32>) -> Result<(), String> {
        let bit = 1_u64 << (index % 64);
        let word = index / 64;
        if let Some(marker) = marker {
            let expected = if self.target_b {
                COMMUNITY_GEN_B
            } else {
                COMMUNITY_GEN_A
            };
            if marker != expected {
                let previous = if self.target_b {
                    COMMUNITY_GEN_A
                } else {
                    COMMUNITY_GEN_B
                };
                if self.recovering
                    && marker == previous
                    && self.present[family][word] & bit != 0
                    && self.generation[family][word] & bit == 0
                    && self.withdrawn[family][word] & bit == 0
                {
                    // Recovery may replay an already-admitted value before its
                    // first target event. It supplies no target coverage.
                    self.announces[family] += 1;
                    return Ok(());
                }
                return Err("wrong generation marker".into());
            }
            if self.target_b && index < self.shape.denied {
                return Err("denied route leaked".into());
            }
            if self.present[family][word] & bit == 0 {
                self.present_count[family] += 1;
            }
            if self.generation[family][word] & bit == 0 {
                self.generation_count[family] += 1;
            }
            self.present[family][word] |= bit;
            self.generation[family][word] |= bit;
            self.announces[family] += 1;
        } else {
            if !self.target_b || index >= self.shape.denied {
                return Err("bystander withdrawal".into());
            }
            if self.present[family][word] & bit == 0 {
                return Err("unknown or duplicate withdrawal".into());
            }
            self.present[family][word] &= !bit;
            self.withdrawn[family][word] |= bit;
            self.present_count[family] -= 1;
            self.withdrawn_count[family] += 1;
            self.withdraws[family] += 1;
        }
        Ok(())
    }

    fn complete(&self) -> bool {
        let denied = if self.target_b { self.shape.denied } else { 0 };
        (0..2).all(|family| {
            self.present_count[family] == self.shape.counts[family] - denied
                && self.generation_count[family] == self.shape.counts[family] - denied
                && self.withdrawn_count[family] == denied
        })
    }

    fn apply(&mut self, parsed: &ParsedUpdate) -> Result<(), String> {
        let has_announcements = !parsed.announced.is_empty() || parsed.attributes.iter().any(|attribute| {
            matches!(attribute, PathAttribute::MpReachNlri(mp) if !mp.announced.is_empty() || !mp.vpn_announced.is_empty())
        });
        let marker = parsed
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::Communities(values) if values.len() == 1 => Some(values[0]),
                _ => None,
            })
            .unwrap_or(if self.target_b {
                COMMUNITY_GEN_B
            } else {
                COMMUNITY_GEN_A
            });
        let origin = parsed
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::AsPath(path) => match path.segments.as_slice() {
                    [AsPathSegment::AsSequence(values)] if values.len() == 1 => Some(values[0]),
                    _ => None,
                },
                _ => None,
            });
        let mut expected = if has_announcements {
            attributes(origin.unwrap_or(ORIGIN_BASE))
        } else {
            Vec::new()
        };
        if has_announcements {
            expected.extend([
                PathAttribute::OriginatorId(stub_open(0, LOCAL_AS, false).bgp_identifier),
                PathAttribute::ClusterList(vec![Ipv4Addr::new(10, 0, 0, 1)]),
                PathAttribute::Communities(vec![marker]),
            ]);
        }
        let common = parsed
            .attributes
            .iter()
            .filter(|attribute| {
                !matches!(
                    attribute,
                    PathAttribute::NextHop(_)
                        | PathAttribute::MpReachNlri(_)
                        | PathAttribute::MpUnreachNlri(_)
                )
            })
            .collect::<Vec<_>>();
        if common.len() != expected.len()
            || expected
                .iter()
                .any(|attribute| !common.contains(&attribute))
        {
            return Err("wrong or extra reflected attributes".into());
        }
        for (code, maximum) in [
            (3, usize::from(!parsed.announced.is_empty())),
            (14, 1),
            (15, 1),
        ] {
            let count = parsed
                .attributes
                .iter()
                .filter(|attribute| attribute.type_code() == code)
                .count();
            if count > maximum || (code == 3 && count != maximum) {
                return Err("duplicate or unexpected family carrier".into());
            }
        }
        reject_update_overlap(parsed)?;
        for entry in &parsed.announced {
            if self.shape.vpn || entry.path_id != 0 {
                return Err("wrong body family/path ID".into());
            }
            if !parsed
                .attributes
                .contains(&PathAttribute::NextHop(Ipv4Addr::new(10, 9, 0, 1)))
            {
                return Err("wrong IPv4 next hop".into());
            }
            let (family, index) = self.shape.index(Prefix::V4(entry.prefix), None)?;
            self.announcement(family, index, marker, origin)?;
        }
        for entry in &parsed.withdrawn {
            if self.shape.vpn || entry.path_id != 0 {
                return Err("wrong withdrawn body family/path ID".into());
            }
            let (family, index) = self.shape.index(Prefix::V4(entry.prefix), None)?;
            self.event(family, index, None)?;
        }
        for attribute in &parsed.attributes {
            match attribute {
                PathAttribute::MpReachNlri(mp) => {
                    let family = self.family(mp.afi, mp.safi)?;
                    if !mp.flowspec_announced.is_empty()
                        || !mp.evpn_announced.is_empty()
                        || !mp.bgpls_announced.is_empty()
                        || !mp.labeled_announced.is_empty()
                        || !mp.rtc_announced.is_empty()
                        || (mp.announced.is_empty() && mp.vpn_announced.is_empty())
                    {
                        return Err("unexpected MP announcement payload".into());
                    }
                    if mp.next_hop != next_hop(family) || mp.link_local_next_hop.is_some() {
                        return Err("wrong MP next hop".into());
                    }
                    if self.shape.vpn {
                        if !mp.announced.is_empty() {
                            return Err("unicast on VPN fixture".into());
                        }
                        for entry in &mp.vpn_announced {
                            let (f, index) = self.vpn_index(entry)?;
                            if f != family || entry.nlri != self.shape.vpn(f, index) {
                                return Err("wrong VPN label or AFI".into());
                            }
                            self.announcement(f, index, marker, origin)?;
                        }
                    } else {
                        if !mp.vpn_announced.is_empty() {
                            return Err("VPN on unicast fixture".into());
                        }
                        for entry in &mp.announced {
                            if entry.path_id != 0 {
                                return Err("unexpected Add-Path".into());
                            }
                            let (f, index) = self.shape.index(entry.prefix, None)?;
                            if f != family {
                                return Err("wrong MP AFI".into());
                            }
                            self.announcement(f, index, marker, origin)?;
                        }
                    }
                }
                PathAttribute::MpUnreachNlri(mp) => {
                    let family = self.family(mp.afi, mp.safi)?;
                    if !mp.flowspec_withdrawn.is_empty()
                        || !mp.evpn_withdrawn.is_empty()
                        || !mp.bgpls_withdrawn.is_empty()
                        || !mp.labeled_withdrawn.is_empty()
                        || !mp.rtc_withdrawn.is_empty()
                        || (self.shape.vpn && !mp.withdrawn.is_empty())
                        || (!self.shape.vpn && !mp.vpn_withdrawn.is_empty())
                    {
                        return Err("unexpected MP withdrawal payload".into());
                    }
                    if self.shape.vpn {
                        for entry in &mp.vpn_withdrawn {
                            let (f, index) = self.vpn_index(entry)?;
                            if f != family {
                                return Err("wrong withdrawal AFI".into());
                            }
                            self.event(f, index, None)?;
                        }
                    } else {
                        for entry in &mp.withdrawn {
                            if entry.path_id != 0 {
                                return Err("unexpected Add-Path".into());
                            }
                            let (f, index) = self.shape.index(entry.prefix, None)?;
                            if f != family {
                                return Err("wrong withdrawal AFI".into());
                            }
                            self.event(f, index, None)?;
                        }
                    }
                }
                _ => {}
            }
        }
        if self.complete() && self.completion_seconds.is_none() {
            self.completion_seconds = self.started.map(|started| started.elapsed().as_secs_f64());
        }
        Ok(())
    }

    fn family(&self, afi: Afi, safi: Safi) -> Result<usize, String> {
        self.shape
            .families()
            .iter()
            .position(|value| *value == (afi, safi))
            .ok_or("unnegotiated MP family".into())
    }

    fn announcement(
        &mut self,
        family: usize,
        index: usize,
        marker: u32,
        origin: Option<u32>,
    ) -> Result<(), String> {
        if origin != Some(self.shape.origin(family, index, marker == COMMUNITY_GEN_B)) {
            return Err("wrong chunk/generation origin AS".into());
        }
        self.event(family, index, Some(marker))
    }

    fn vpn_index(&self, entry: &VpnNlriEntry) -> Result<(usize, usize), String> {
        if entry.path_id != 0 {
            return Err("unexpected VPN Add-Path".into());
        }
        let prefix = match entry.nlri.prefix {
            VpnPrefix::V4 { addr, len } => Prefix::V4(Ipv4Prefix::new(addr, len)),
            VpnPrefix::V6 { addr, len } => Prefix::V6(Ipv6Prefix::new(addr, len)),
        };
        self.shape
            .index(prefix, Some(entry.nlri.route_distinguisher))
    }
}

fn reject_update_overlap(parsed: &ParsedUpdate) -> Result<(), String> {
    let withdrawn_mp = parsed
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        });
    if parsed.withdrawn.is_empty()
        && withdrawn_mp.is_none_or(|mp| mp.withdrawn.is_empty() && mp.vpn_withdrawn.is_empty())
    {
        return Ok(());
    }
    // This fixture never requires a same-key withdraw/announce within an
    // UPDATE. Reject it before folding either event: carrier order cannot
    // conceal a prior-value replay after withdrawal or a spurious transient.
    for entry in &parsed.announced {
        if parsed.withdrawn.contains(entry)
            || withdrawn_mp.is_some_and(|mp| {
                mp.afi == Afi::Ipv4
                    && mp.safi == Safi::Unicast
                    && mp.withdrawn.contains(&NlriEntry {
                        path_id: entry.path_id,
                        prefix: Prefix::V4(entry.prefix),
                    })
            })
        {
            return Err("same-key announcement and withdrawal in one UPDATE".into());
        }
    }
    for attribute in &parsed.attributes {
        let PathAttribute::MpReachNlri(mp) = attribute else {
            continue;
        };
        for entry in &mp.announced {
            let body_overlap = mp.afi == Afi::Ipv4
                && mp.safi == Safi::Unicast
                && parsed.withdrawn.iter().any(|withdrawn| {
                    entry.path_id == withdrawn.path_id
                        && entry.prefix == Prefix::V4(withdrawn.prefix)
                });
            if body_overlap
                || withdrawn_mp.is_some_and(|withdrawn| {
                    withdrawn.afi == mp.afi
                        && withdrawn.safi == mp.safi
                        && withdrawn.withdrawn.contains(entry)
                })
            {
                return Err("same-key announcement and withdrawal in one UPDATE".into());
            }
        }
        for entry in &mp.vpn_announced {
            if withdrawn_mp.is_some_and(|withdrawn| {
                withdrawn.afi == mp.afi
                    && withdrawn.safi == mp.safi
                    && withdrawn.vpn_withdrawn.iter().any(|old| {
                        old.path_id == entry.path_id && old.nlri.key() == entry.nlri.key()
                    })
            }) {
                return Err("same-key announcement and withdrawal in one UPDATE".into());
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Default)]
struct Pause {
    epoch: u32,
    paused: bool,
}

struct Receiver {
    inventory: Arc<Mutex<Inventory>>,
    control: watch::Sender<Pause>,
    acknowledged: Arc<AtomicU32>,
    live: Arc<AtomicBool>,
}

async fn receive(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    receiver: Arc<Receiver>,
    mut pause: watch::Receiver<Pause>,
) -> Result<(), String> {
    let mut buffer = BytesMut::with_capacity(8192);
    loop {
        let requested = *pause.borrow_and_update();
        receiver
            .acknowledged
            .store(requested.epoch, Ordering::Release);
        if requested.paused {
            pause
                .changed()
                .await
                .map_err(|_| "pause owner disappeared")?;
            continue;
        }
        tokio::select! {
            biased;
            changed = pause.changed() => { changed.map_err(|_| "pause owner disappeared")?; }
            read = reader.read_buf(&mut buffer) => {
                if read.map_err(|error| error.to_string())? == 0 { return Err("session closed".into()); }
                while let Some(length) = peek_message_length(&buffer, MAX_MESSAGE_LEN).map_err(|error| error.to_string())? {
                    if buffer.len() < usize::from(length) { break; }
                    let mut frame = buffer.split_to(usize::from(length)).freeze();
                    match decode_message(&mut frame, MAX_MESSAGE_LEN).map_err(|error| error.to_string())? {
                        Message::Keepalive => {}
                        Message::Update(update) => {
                            let parsed = update.parse(true, false, &[]).map_err(|error| error.to_string())?;
                            receiver.inventory.lock().unwrap().apply(&parsed)?;
                        }
                        _ => return Err("unexpected BGP message or reset".into()),
                    }
                }
            }
        }
    }
}

async fn receive_live(
    reader: tokio::net::tcp::OwnedReadHalf,
    receiver: Arc<Receiver>,
    pause: watch::Receiver<Pause>,
) {
    if let Err(error) = receive(reader, receiver.clone(), pause).await {
        receiver.inventory.lock().unwrap().error = Some(error);
    }
    receiver.live.store(false, Ordering::Release);
}

fn terminal_state(receivers: &[Arc<Receiver>], source_live: &AtomicBool) -> Result<(), String> {
    if !source_live.load(Ordering::Acquire) {
        return Err("source session ended".into());
    }
    for receiver in receivers {
        let inventory = receiver.inventory.lock().unwrap();
        if let Some(error) = &inventory.error {
            return Err(error.clone());
        }
        if !receiver.live.load(Ordering::Acquire) || !inventory.complete() {
            return Err("receiver session ended or final inventory incomplete".into());
        }
    }
    Ok(())
}

fn source_message(message: Message, shape: Shape) -> Result<(), String> {
    match message {
        Message::Keepalive => Ok(()),
        Message::Update(update) => {
            let parsed = update
                .parse(true, false, &[])
                .map_err(|error| error.to_string())?;
            if !parsed.announced.is_empty() || !parsed.withdrawn.is_empty() {
                return Err("route reflected back to its source".into());
            }
            // Normal initial feeds send EoR even without GR. Accept only exact
            // empty carriers for negotiated families, never an arbitrary UPDATE.
            if parsed.attributes.is_empty() && !shape.vpn {
                return Ok(());
            }
            let [PathAttribute::MpUnreachNlri(mp)] = parsed.attributes.as_slice() else {
                return Err("source received non-EoR UPDATE".into());
            };
            if shape.families().contains(&(mp.afi, mp.safi))
                && mp.withdrawn.is_empty()
                && mp.vpn_withdrawn.is_empty()
                && mp.flowspec_withdrawn.is_empty()
                && mp.evpn_withdrawn.is_empty()
                && mp.bgpls_withdrawn.is_empty()
                && mp.labeled_withdrawn.is_empty()
                && mp.rtc_withdrawn.is_empty()
            {
                Ok(())
            } else {
                Err("source received unexpected EoR family/payload".into())
            }
        }
        _ => Err("source received reset or unexpected message".into()),
    }
}

async fn connect(shape: Shape, port: u16, index: u32) -> Result<TcpStream, String> {
    let mut open = stub_open(index, LOCAL_AS, false);
    open.capabilities = shape
        .families()
        .map(|(afi, safi)| Capability::MultiProtocol { afi, safi })
        .into_iter()
        .collect();
    open.capabilities
        .push(Capability::FourOctetAs { asn: LOCAL_AS });
    let bytes = encode_message(&Message::Open(open)).map_err(|error| error.to_string())?;
    let keepalive = encode_message(&Message::Keepalive).unwrap();
    let (stream, _, _) = establish_stream_with_retry_and_receive_buffer(
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
        stub_addr(index),
        &bytes,
        &keepalive,
        CONNECT_WINDOW,
        &shape.families(),
        (index != 0).then_some(RECEIVER_BUFFER),
    )
    .await?;
    if index != 0
        && socket2::SockRef::from(&stream)
            .recv_buffer_size()
            .map_err(|error| error.to_string())?
            != 2 * RECEIVER_BUFFER
    {
        return Err("receiver buffer differs from fixed Linux fixture".into());
    }
    Ok(stream)
}

async fn wait_for(
    receivers: &[Arc<Receiver>],
    test: impl Fn(&Receiver) -> bool,
) -> Result<(), String> {
    tokio::time::timeout(CELL_DEADLINE, async {
        loop {
            for receiver in receivers {
                if !receiver.live.load(Ordering::Acquire) {
                    return Err("receiver session ended".into());
                }
                if let Some(error) = receiver.inventory.lock().unwrap().error.clone() {
                    return Err(error);
                }
            }
            if receivers.iter().all(|receiver| test(receiver)) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "fixed cell deadline expired")?
}

fn readiness_failure_record(
    sequence: u64,
    metrics: SocketAddr,
    trace: &HttpFetchTrace,
    error: &str,
    started: Instant,
    finished: Option<Instant>,
    clocks: (Option<f64>, Option<f64>),
) -> String {
    let elapsed = finished.map(|end| end.saturating_duration_since(started));
    let after_start = |at: Option<Instant>| {
        json_seconds(at.map(|at| at.saturating_duration_since(started).as_secs_f64()))
    };
    let elapsed_seconds = json_seconds(elapsed.map(|value| value.as_secs_f64()));
    let overshoot = json_seconds(elapsed.map(|value| {
        value
            .saturating_sub(READINESS_REQUEST_DEADLINE)
            .as_secs_f64()
    }));
    let connected = matches!(
        trace.phase,
        "request_write" | "response_read_to_eof" | "response_validation"
    );
    let written = matches!(trace.phase, "response_read_to_eof" | "response_validation");
    format!(
        "mass_dirty_readiness_failure {{\"attempt_sequence\":{sequence},\"endpoint\":\"{metrics}\",\"path\":\"/readyz\",\"deadline_ms\":1000,\"phase\":\"{}\",\"tcp_connected\":{connected},\"request_written\":{written},\"response_read_completed\":{},\"response_bytes\":{},\"response_prefix_hex\":\"{}\",\"response_prefix_truncated\":{},\"prefix_limit_bytes\":{HTTP_TRACE_PREFIX_BYTES},\"error_bytes\":{},\"error_prefix_hex\":\"{}\",\"error_prefix_truncated\":{},\"started_monotonic_seconds\":{},\"finished_monotonic_seconds\":{},\"observed_elapsed_seconds\":{elapsed_seconds},\"deadline_overshoot_seconds\":{overshoot},\"connected_after_seconds\":{},\"request_written_after_seconds\":{},\"read_completed_after_seconds\":{}}}",
        trace.phase,
        trace.phase == "response_validation",
        trace.response.len(),
        diagnostic_hex(&trace.response),
        trace.response.len() > HTTP_TRACE_PREFIX_BYTES,
        error.len(),
        diagnostic_hex(error.as_bytes()),
        error.len() > HTTP_TRACE_PREFIX_BYTES,
        json_seconds(clocks.0),
        json_seconds(clocks.1),
        after_start(trace.connected_at),
        after_start(trace.request_written_at),
        after_start(trace.read_completed_at),
    )
}

/// Status code from a raw HTTP response line, if one was read.
fn http_status(response: &[u8]) -> Option<u16> {
    let line = response.split(|&byte| byte == b'\n').next()?;
    std::str::from_utf8(line)
        .ok()?
        .split_ascii_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

async fn readiness_watch(
    metrics: SocketAddr,
    mut stop: oneshot::Receiver<()>,
    correctness: bool,
) -> Result<u64, String> {
    let mut tick = tokio::time::interval(READINESS_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut samples = 0;
    loop {
        tokio::select! {
            _ = &mut stop => return Ok(samples),
            _ = tick.tick() => {
                let started = Instant::now();
                let probe_start = monotonic_seconds(correctness)?;
                // Reuse the HTTP validation; the request deadline bounds a wedge.
                let mut trace = HttpFetchTrace { record_clocks: !correctness, ..HttpFetchTrace::default() };
                let fetched = fetch_http_traced(metrics, "/readyz", started + READINESS_REQUEST_DEADLINE, Some(&mut trace)).await;
                let elapsed = started.elapsed();
                samples += 1;
                // A diagnostic clock failure must not replace an HTTP error.
                let probe_end = if fetched.is_ok() { monotonic_seconds(correctness)? } else { monotonic_seconds(correctness).ok().flatten() };
                let (status, phase) = match &fetched {
                    Ok(_) => ("200".to_owned(), "null".to_owned()),
                    Err(error) => {
                        eprintln!("{}", readiness_failure_record(samples, metrics, &trace, error, started, (!correctness).then(Instant::now), (probe_start, probe_end)));
                        (http_status(&trace.response).map_or_else(|| "null".into(), |code| code.to_string()), format!("\"{}\"", trace.phase))
                    }
                };
                let seconds = if correctness { "null".into() } else { elapsed.as_secs_f64().to_string() };
                let probe_start = json_seconds(probe_start);
                let probe_end = json_seconds(probe_end);
                println!("mass_dirty_readiness {{\"sequence\":{samples},\"status\":{status},\"phase\":{phase},\"request_deadline_ms\":1000,\"elapsed_seconds\":{seconds},\"started_monotonic_seconds\":{probe_start},\"finished_monotonic_seconds\":{probe_end}}}");
            }
        }
    }
}

fn checked_clock_seconds(seconds: libc::time_t, nanoseconds: libc::c_long) -> Result<f64, String> {
    let seconds = u64::try_from(seconds).map_err(|_| "negative monotonic seconds")?;
    let nanoseconds = u32::try_from(nanoseconds).map_err(|_| "invalid monotonic nanoseconds")?;
    if nanoseconds >= 1_000_000_000 {
        return Err("invalid monotonic nanoseconds".into());
    }
    Ok(Duration::new(seconds, nanoseconds).as_secs_f64())
}

fn monotonic_seconds(correctness: bool) -> Result<Option<f64>, String> {
    if correctness {
        return Ok(None);
    }
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: timestamp is writable and correctly aligned. The fixed Linux
    // clock matches Python time.monotonic(), so raw probes and controller
    // phases share an epoch without a wall-clock mapping or drift assumption.
    // Check the syscall and both fields before converting through Duration.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut timestamp) } != 0 {
        return Err(format!(
            "monotonic clock failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    checked_clock_seconds(timestamp.tv_sec, timestamp.tv_nsec).map(Some)
}

fn json_seconds(seconds: Option<f64>) -> String {
    seconds.map_or_else(|| "null".into(), |seconds| seconds.to_string())
}

async fn run(args: &[String]) -> Result<(), String> {
    let correctness = args.iter().any(|value| value == "--correctness-only");
    let value = |name: &str| -> Result<&str, String> {
        let position = args
            .iter()
            .position(|value| value == name)
            .ok_or_else(|| format!("missing {name}"))?;
        args.get(position + 1)
            .map(String::as_str)
            .ok_or_else(|| format!("missing value for {name}"))
    };
    let pressure = match value("--cohort")? {
        "no-refusal" => false,
        "cap-pressure" => true,
        _ => return Err("cohort must be no-refusal or cap-pressure".into()),
    };
    let shape = Shape::new(value("--profile")?, pressure)?;
    let count: u32 = value("--receivers")?
        .parse()
        .map_err(|_| "bad receiver count")?;
    if !(1..=64).contains(&count) {
        return Err("receivers must be 1..=64".into());
    }
    let port: u16 = value("--bgp-port")?.parse().map_err(|_| "bad BGP port")?;
    let metrics: SocketAddr = value("--metrics-addr")?
        .parse()
        .map_err(|_| "bad metrics address")?;
    if !metrics.ip().is_loopback() {
        return Err("metrics must be loopback".into());
    }
    let mut receivers = Vec::new();
    for index in 1..=count {
        let stream = connect(shape, port, index).await?;
        let (reader, mut writer) = stream.into_split();
        let (control, pause) = watch::channel(Pause::default());
        let receiver = Arc::new(Receiver {
            inventory: Arc::new(Mutex::new(Inventory::new(shape))),
            control,
            acknowledged: Arc::new(AtomicU32::new(0)),
            live: Arc::new(AtomicBool::new(true)),
        });
        tokio::spawn(receive_live(reader, receiver.clone(), pause));
        let writer_receiver = receiver.clone();
        tokio::spawn(async move {
            let bytes = encode_message(&Message::Keepalive).unwrap();
            loop {
                if writer.write_all(&bytes).await.is_err() {
                    writer_receiver.live.store(false, Ordering::Release);
                    return;
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
        receivers.push(receiver);
    }
    let source = connect(shape, port, 0).await?;
    let (mut source_reader, mut source_writer) = source.into_split();
    let (updates, mut outgoing) = mpsc::channel::<SourceWrite>(8);
    let source_live = Arc::new(AtomicBool::new(true));
    let source_write_status = source_live.clone();
    tokio::spawn(async move {
        let bytes = encode_message(&Message::Keepalive).unwrap();
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            let result = tokio::select! {
                _ = tick.tick() => source_writer.write_all(&bytes).await,
                message = outgoing.recv() => {
                    let Some((message, drained)) = message else { return; };
                    let result = match encode_message(&message) {
                        Ok(bytes) => source_writer.write_all(&bytes).await,
                        Err(_) => { source_write_status.store(false, Ordering::Release); return; }
                    };
                    if let Some(drained) = drained {
                        let flushed = if result.is_ok() { source_writer.flush().await } else { result };
                        let failed = flushed.is_err();
                        let _ = drained.send(flushed.map_err(|error| error.to_string()));
                        if failed { source_write_status.store(false, Ordering::Release); return; }
                        continue;
                    }
                    result
                }
            };
            if result.is_err() {
                source_write_status.store(false, Ordering::Release);
                return;
            }
        }
    });
    let source_status = source_live.clone();
    tokio::spawn(async move {
        let mut buffer = BytesMut::with_capacity(8192);
        'read: while source_reader
            .read_buf(&mut buffer)
            .await
            .is_ok_and(|read| read != 0)
        {
            loop {
                let length = match peek_message_length(&buffer, MAX_MESSAGE_LEN) {
                    Ok(Some(length)) => length,
                    Ok(None) => break,
                    Err(_) => break 'read,
                };
                if buffer.len() < usize::from(length) {
                    break;
                }
                let mut frame = buffer.split_to(usize::from(length)).freeze();
                if decode_message(&mut frame, MAX_MESSAGE_LEN)
                    .map_err(|error| error.to_string())
                    .and_then(|message| source_message(message, shape))
                    .is_err()
                {
                    break 'read;
                }
            }
        }
        source_status.store(false, Ordering::Release);
    });
    feed_generation(&updates, shape, false, false).await?;
    wait_for(&receivers, |receiver| {
        receiver.inventory.lock().unwrap().complete()
    })
    .await?;
    terminal_state(&receivers, &source_live)?;
    println!(
        "mass_dirty_ready {{\"receivers\":{count},\"family_keys\":[{},{}],\"bitmap_bytes\":{},\"correctness_only\":{correctness},\"batch_size\":{},\"origin_cardinality\":{},\"baseline_eor_messages\":2,\"receiver_receive_buffer_bytes\":{}}}",
        shape.counts[0],
        shape.counts[1],
        count as usize
            * shape
                .counts
                .map(|n| n.div_ceil(64) * 8 * 3)
                .iter()
                .sum::<usize>(),
        shape.batch_size, shape.chunks(), RECEIVER_BUFFER * 2
    );
    let (stop, stopped) = oneshot::channel();
    let mut readiness = tokio::spawn(readiness_watch(metrics, stopped, correctness));
    let protocol = async {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        for (epoch, generation) in [(1, "b"), (2, "a")] {
            let pause = lines
                .next_line()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("controller ended")?;
            if pause != format!("pause {generation}") {
                return Err("unexpected controller pause".into());
            }
            for receiver in &receivers {
                receiver.control.send_replace(Pause {
                    epoch,
                    paused: true,
                });
            }
            wait_for(&receivers, |receiver| {
                receiver.acknowledged.load(Ordering::Acquire) == epoch
            })
            .await?;
            for receiver in &receivers {
                receiver.inventory.lock().unwrap().arm(generation == "b");
            }
            println!("mass_dirty_paused {{\"generation\":\"{generation}\",\"receivers\":{count}}}");
            if lines
                .next_line()
                .await
                .map_err(|error| error.to_string())?
                .as_deref()
                != Some(&format!("churn {generation}"))
            {
                return Err("unexpected source churn command".into());
            }
            feed_generation(&updates, shape, generation == "b", true).await?;
            if !source_live.load(Ordering::Acquire) {
                return Err("source session ended during churn".into());
            }
            let drained = json_seconds(monotonic_seconds(correctness)?);
            println!("mass_dirty_sent {{\"generation\":\"{generation}\",\"family_keys\":[{},{}],\"announcement_messages\":{},\"eor_messages\":{},\"origin_cardinality\":{},\"writer_drained\":true,\"drained_monotonic_seconds\":{drained}}}", shape.counts[0], shape.counts[1], shape.chunks(), shape.chunks(), shape.chunks());
            let resume = lines
                .next_line()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("controller ended")?;
            if resume != format!("resume {generation}") {
                return Err("unexpected controller resume".into());
            }
            let started = (!correctness).then(Instant::now);
            for receiver in &receivers {
                receiver.inventory.lock().unwrap().started = started;
                receiver.control.send_replace(Pause {
                    epoch: epoch + 2,
                    paused: false,
                });
            }
            wait_for(&receivers, |receiver| {
                receiver.inventory.lock().unwrap().complete()
            })
            .await?;
            if !source_live.load(Ordering::Acquire) {
                return Err("source session ended".into());
            }
            let mut durations = receivers
                .iter()
                .filter_map(|receiver| receiver.inventory.lock().unwrap().completion_seconds)
                .collect::<Vec<_>>();
            durations.sort_by(f64::total_cmp);
            let p50 = if correctness {
                "null".into()
            } else {
                durations
                    .get(durations.len() / 2)
                    .ok_or("missing receiver completion")?
                    .to_string()
            };
            let maximum = if correctness {
                "null".into()
            } else {
                durations
                    .last()
                    .ok_or("missing receiver completion")?
                    .to_string()
            };
            let withdrawals: u64 = receivers
                .iter()
                .map(|receiver| {
                    receiver
                        .inventory
                        .lock()
                        .unwrap()
                        .withdraws
                        .iter()
                        .sum::<u64>()
                })
                .sum();
            println!(
                "mass_dirty_complete {{\"generation\":\"{generation}\",\"receivers\":{count},\"resume_to_fold_p50_seconds\":{p50},\"resume_to_fold_max_seconds\":{maximum},\"withdrawals\":{withdrawals},\"exact_fold\":true,\"sessions_continuous\":true}}"
            );
        }
        if lines
            .next_line()
            .await
            .map_err(|error| error.to_string())?
            .as_deref()
            != Some("finish")
        {
            return Err("missing controller finish boundary".into());
        }
        Ok::<(), String>(())
    };
    // Observe watcher failure while any controller command/source/wire wait is
    // pending. Waiting until finish can strand the controller waiting for a
    // post-fold sample that an already-failed watcher will never produce.
    tokio::select! {
        result = protocol => result?,
        result = &mut readiness => {
            result.map_err(|error| error.to_string())??;
            return Err("readiness stopped before controller finish".into());
        }
    }
    // A watcher that failed exactly at the finish boundary has dropped its
    // receiver. Join it anyway so its original error is never replaced.
    let _ = stop.send(());
    let samples = readiness.await.map_err(|error| error.to_string())??;
    if samples == 0 {
        return Err("no readiness samples".into());
    }
    // The controller may retain the final fold while sampling ownership/memory.
    // Recheck actual reader errors, continuity and inventory at its finish boundary.
    terminal_state(&receivers, &source_live)?;
    println!(
        "mass_dirty_exit {{\"readiness_samples\":{samples},\"readiness_interval_ms\":250,\"readiness_request_deadline_ms\":1000,\"status\":\"PASS\"}}"
    );
    Ok(())
}

pub(super) fn main(args: &[String]) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    if let Err(error) = runtime.block_on(run(args)) {
        eprintln!("mass-dirty qualification failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_mass_dirty_same_update_overlap_cannot_hide_a_per_key_transient() {
        for vpn in [false, true] {
            let shape = Shape {
                vpn,
                counts: [2, 2],
                denied: 1,
                batch_size: 80,
            };
            for family in 0..2 {
                for reverse in [false, true] {
                    for disjoint in [false, true] {
                        let mut parsed = parsed_wire(&reflected(shape, family, Vec::new()));
                        if !vpn && family == 0 {
                            if disjoint {
                                parsed.announced.remove(0);
                            }
                            parsed.withdrawn.push(Ipv4NlriEntry {
                                path_id: 0,
                                prefix: match shape.prefix(0, 0) {
                                    Prefix::V4(prefix) => prefix,
                                    Prefix::V6(_) => unreachable!(),
                                },
                            });
                        } else {
                            if disjoint {
                                for attribute in &mut parsed.attributes {
                                    if let PathAttribute::MpReachNlri(mp) = attribute {
                                        if vpn {
                                            mp.vpn_announced.remove(0);
                                        } else {
                                            mp.announced.remove(0);
                                        }
                                    }
                                }
                            }
                            let mut withdrawal = parsed_wire(&end_of_rib(shape, family).unwrap())
                                .attributes
                                .remove(0);
                            let PathAttribute::MpUnreachNlri(mp) = &mut withdrawal else {
                                unreachable!()
                            };
                            if vpn {
                                mp.vpn_withdrawn.push(VpnNlriEntry {
                                    path_id: 0,
                                    nlri: shape.vpn(family, 0),
                                });
                            } else {
                                mp.withdrawn.push(NlriEntry {
                                    path_id: 0,
                                    prefix: shape.prefix(family, 0),
                                });
                            }
                            parsed.attributes.push(withdrawal);
                        }
                        if reverse {
                            parsed.attributes.reverse();
                        }
                        let message = Message::Update(
                            UpdateMessage::try_build(
                                &parsed.announced,
                                &parsed.withdrawn,
                                &parsed.attributes,
                                true,
                                false,
                                Ipv4UnicastMode::Body,
                            )
                            .unwrap(),
                        );
                        let parsed = parsed_wire(&message);
                        let mut inventory = Inventory::new(shape);
                        for baseline_family in 0..2 {
                            inventory
                                .apply(&parsed_wire(&reflected(shape, baseline_family, Vec::new())))
                                .unwrap();
                        }
                        inventory.arm(true);
                        if disjoint {
                            // In VPN this is the same prefix in another raw RD.
                            inventory.apply(&parsed).unwrap();
                            assert_eq!(inventory.withdrawn_count[family], 1);
                        } else {
                            let old_present = inventory.present.clone();
                            assert_eq!(
                                inventory.apply(&parsed).unwrap_err(),
                                "same-key announcement and withdrawal in one UPDATE"
                            );
                            assert_eq!(inventory.present, old_present);
                            assert_eq!(inventory.withdrawn_count, [0, 0]);
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn recovery_mass_dirty_churn_fences_each_chunk_and_waits_for_final_writer_drain() {
        for vpn in [false, true] {
            let shape = Shape {
                vpn,
                counts: [2, 2],
                denied: 0,
                batch_size: 1,
            };
            let (sender, mut messages) = mpsc::channel(8);
            let feed =
                tokio::spawn(async move { feed_generation(&sender, shape, true, true).await });
            let mut final_drain = None;
            for family in 0..2 {
                for index in 0..shape.counts[family] {
                    let (message, drain) = messages.recv().await.unwrap();
                    assert!(drain.is_none());
                    let parsed = parsed_wire(&message);
                    assert!(parsed.attributes.contains(&PathAttribute::AsPath(AsPath {
                        segments: vec![AsPathSegment::AsSequence(vec![
                            shape.origin(family, index, true)
                        ])],
                    })));
                    assert_eq!(
                        shape.origin(family, index, true),
                        ORIGIN_BASE + 2 * u32::try_from(family * 2 + index).unwrap() + 1
                    );
                    let (message, drain) = messages.recv().await.unwrap();
                    source_message(message, shape).unwrap();
                    if family == 1 && index == 1 {
                        final_drain = drain;
                    } else {
                        assert!(drain.is_none());
                    }
                }
            }
            // Receiving the final message proves the producer ran through all
            // enqueue operations, but completion still owes actual writer ACK.
            assert!(!feed.is_finished());
            final_drain.unwrap().send(Ok(())).unwrap();
            feed.await.unwrap().unwrap();
        }
    }

    #[test]
    fn recovery_mass_dirty_chunk_origin_is_part_of_exact_wire_identity() {
        for vpn in [false, true] {
            let shape = Shape {
                vpn,
                counts: [2, 2],
                denied: 0,
                batch_size: 80,
            };
            let valid = parsed_wire(&reflected(shape, 1, Vec::new()));
            let mut wrong = valid.clone();
            for attribute in &mut wrong.attributes {
                if let PathAttribute::AsPath(path) = attribute {
                    path.segments =
                        vec![AsPathSegment::AsSequence(vec![shape.origin(0, 0, false)])];
                }
            }
            Inventory::new(shape).apply(&valid).unwrap();
            assert!(Inventory::new(shape).apply(&wrong).is_err());
            assert!(announce(shape, 0, 0, 0, false).is_err());
            let single = Shape {
                batch_size: 1,
                ..shape
            };
            assert!(announce(single, 0, 0, 2, false).is_err());
        }
        let shape = Shape::new("full-uc", false).unwrap();
        assert_eq!(shape.chunks(), 15_375);
        assert_eq!(shape.origin(1, 229_999, true), 4_200_130_749);
        assert_ne!(shape.origin(0, 0, false), LOCAL_AS);
    }

    #[test]
    fn recovery_mass_dirty_clock_checks_fields_and_keeps_correctness_timing_null() {
        assert_eq!(monotonic_seconds(true).unwrap(), None);
        assert_eq!(json_seconds(None), "null");
        assert_eq!(checked_clock_seconds(2, 500_000_000).unwrap(), 2.5);
        assert!(checked_clock_seconds(-1, 0).is_err());
        assert!(checked_clock_seconds(0, -1).is_err());
        assert!(checked_clock_seconds(0, 1_000_000_000).is_err());
        assert!(checked_clock_seconds(libc::time_t::MAX, 999_999_999)
            .unwrap()
            .is_finite());
    }

    #[test]
    fn recovery_mass_dirty_readiness_failure_keeps_clocks_null_and_prefix_bounded() {
        let trace = HttpFetchTrace {
            phase: "response_read_to_eof",
            response: vec![b'x'; HTTP_TRACE_PREFIX_BYTES + 7],
            ..HttpFetchTrace::default()
        };
        let record = readiness_failure_record(
            210,
            "127.0.0.1:19186".parse().unwrap(),
            &trace,
            "deadline \"\n",
            Instant::now(),
            None,
            (None, None),
        );
        assert!(record.contains("\"attempt_sequence\":210"));
        assert!(record.contains("\"response_bytes\":519"));
        assert!(record.contains("\"response_prefix_truncated\":true"));
        assert!(record.contains(&format!(
            "\"response_prefix_hex\":\"{}\"",
            "78".repeat(HTTP_TRACE_PREFIX_BYTES)
        )));
        assert!(record.contains("\"error_prefix_hex\":\"646561646c696e6520220a\""));
        assert!(record.contains(
            "\"tcp_connected\":true,\"request_written\":true,\"response_read_completed\":false"
        ));
        for field in [
            "started_monotonic_seconds",
            "finished_monotonic_seconds",
            "observed_elapsed_seconds",
            "deadline_overshoot_seconds",
            "connected_after_seconds",
            "request_written_after_seconds",
            "read_completed_after_seconds",
        ] {
            assert!(record.contains(&format!("\"{field}\":null")));
        }
        assert_eq!(record.lines().count(), 1);
    }

    #[test]
    fn recovery_mass_dirty_readiness_failure_records_measured_boundaries_and_overshoot() {
        let started = Instant::now();
        let trace = HttpFetchTrace {
            record_clocks: true,
            phase: "response_validation",
            connected_at: Some(started + Duration::from_millis(1)),
            request_written_at: Some(started + Duration::from_millis(2)),
            read_completed_at: Some(started + Duration::from_millis(300)),
            ..HttpFetchTrace::default()
        };
        let record = readiness_failure_record(
            2,
            "127.0.0.1:19186".parse().unwrap(),
            &trace,
            "/readyz checkpoint exceeded deadline",
            started,
            Some(started + Duration::from_millis(1025)),
            (Some(10.0), Some(11.025)),
        );
        for field in [
            "\"started_monotonic_seconds\":10",
            "\"finished_monotonic_seconds\":11.025",
            "\"observed_elapsed_seconds\":1.025",
            "\"deadline_overshoot_seconds\":0.025",
            "\"connected_after_seconds\":0.001",
            "\"request_written_after_seconds\":0.002",
            "\"read_completed_after_seconds\":0.3",
            "\"response_read_completed\":true",
        ] {
            assert!(record.contains(field), "missing {field}: {record}");
        }
    }

    #[test]
    fn recovery_mass_dirty_readiness_sample_reports_actual_status() {
        assert_eq!(
            http_status(b"HTTP/1.1 503 Service Unavailable\r\n\r\n"),
            Some(503)
        );
        assert_eq!(
            http_status(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            Some(200)
        );
        assert_eq!(http_status(b""), None);
        assert_eq!(http_status(b"HTTP/1.1"), None);
    }

    fn reflected(shape: Shape, family: usize, extras: Vec<PathAttribute>) -> Message {
        let Message::Update(update) =
            announce(shape, family, 0, shape.counts[family], false).unwrap()
        else {
            unreachable!();
        };
        let mut parsed = update.parse(true, false, &[]).unwrap();
        parsed.attributes.extend([
            PathAttribute::OriginatorId(stub_open(0, LOCAL_AS, false).bgp_identifier),
            PathAttribute::ClusterList(vec![Ipv4Addr::new(10, 0, 0, 1)]),
            PathAttribute::Communities(vec![COMMUNITY_GEN_A]),
        ]);
        parsed.attributes.extend(extras);
        Message::Update(
            UpdateMessage::try_build(
                &parsed.announced,
                &parsed.withdrawn,
                &parsed.attributes,
                true,
                false,
                Ipv4UnicastMode::Body,
            )
            .unwrap(),
        )
    }

    fn parsed_wire(message: &Message) -> ParsedUpdate {
        let mut bytes = bytes::Bytes::from(encode_message(message).unwrap());
        let Message::Update(update) = decode_message(&mut bytes, MAX_MESSAGE_LEN).unwrap() else {
            panic!("UPDATE expected");
        };
        update.parse(true, false, &[]).unwrap()
    }

    #[test]
    fn recovery_mass_dirty_complete_attributes_reject_extra_and_duplicate_semantics() {
        for vpn in [false, true] {
            let shape = Shape {
                vpn,
                counts: [2, 2],
                denied: 0,
                batch_size: 80,
            };
            for family in 0..2 {
                let mut inventory = Inventory::new(shape);
                let mut valid = parsed_wire(&reflected(shape, family, Vec::new()));
                valid.attributes.reverse();
                inventory.apply(&valid).unwrap();
                for extra in [
                    PathAttribute::Med(123),
                    PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
                        flags: 0xc0,
                        type_code: 250,
                        data: bytes::Bytes::from_static(&[1, 2]),
                    }),
                ] {
                    let parsed = parsed_wire(&reflected(shape, family, vec![extra]));
                    assert!(Inventory::new(shape).apply(&parsed).is_err());
                }
                valid.attributes.push(PathAttribute::Origin(Origin::Igp));
                assert!(Inventory::new(shape).apply(&valid).is_err());
            }
        }
    }

    #[test]
    fn recovery_mass_dirty_source_accepts_only_negotiated_empty_eor_and_keepalive() {
        for vpn in [false, true] {
            let shape = Shape {
                vpn,
                counts: [2, 2],
                denied: 0,
                batch_size: 80,
            };
            source_message(Message::Keepalive, shape).unwrap();
            for (afi, safi) in shape.families() {
                let attributes = [PathAttribute::MpUnreachNlri(Box::new(MpUnreachNlri {
                    afi,
                    safi,
                    withdrawn: Vec::new(),
                    flowspec_withdrawn: Vec::new(),
                    evpn_withdrawn: Vec::new(),
                    bgpls_withdrawn: Vec::new(),
                    vpn_withdrawn: Vec::new(),
                    labeled_withdrawn: Vec::new(),
                    rtc_withdrawn: Vec::new(),
                }))];
                let eor = Message::Update(
                    UpdateMessage::try_build(
                        &[],
                        &[],
                        &attributes,
                        true,
                        false,
                        Ipv4UnicastMode::Body,
                    )
                    .unwrap(),
                );
                source_message(eor.clone(), shape).unwrap();
                let opposite = Shape { vpn: !vpn, ..shape };
                assert!(source_message(eor, opposite).is_err());
            }
            assert!(source_message(reflected(shape, 0, Vec::new()), shape).is_err());
        }
    }

    #[tokio::test]
    async fn recovery_mass_dirty_final_boundary_rejects_observed_late_update_or_disconnect() {
        let shape = Shape {
            vpn: false,
            counts: [2, 2],
            denied: 0,
            batch_size: 80,
        };
        for disconnect in [false, true] {
            let mut inventory = Inventory::new(shape);
            for family in 0..2 {
                inventory
                    .apply(&parsed_wire(&reflected(shape, family, Vec::new())))
                    .unwrap();
            }
            assert!(inventory.complete());
            let (control, pause) = watch::channel(Pause::default());
            let receiver = Arc::new(Receiver {
                inventory: Arc::new(Mutex::new(inventory)),
                control,
                acknowledged: Arc::new(AtomicU32::new(0)),
                live: Arc::new(AtomicBool::new(true)),
            });
            let source_live = AtomicBool::new(true);
            terminal_state(std::slice::from_ref(&receiver), &source_live).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut sender = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, _writer) = stream.into_split();
            let task = tokio::spawn(receive_live(reader, receiver.clone(), pause));
            if disconnect {
                drop(sender);
            } else {
                let bad = reflected(shape, 0, vec![PathAttribute::Med(123)]);
                sender
                    .write_all(&encode_message(&bad).unwrap())
                    .await
                    .unwrap();
            }
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            assert!(terminal_state(std::slice::from_ref(&receiver), &source_live).is_err());
        }
    }

    #[test]
    fn recovery_mass_dirty_raw_rd_label_and_path_identity() {
        let shape = Shape {
            vpn: true,
            counts: [16, 16],
            denied: 0,
            batch_size: 80,
        };
        let inventory = Inventory::new(shape);
        for family in 0..2 {
            for index in 0..shape.counts[family] {
                let mut entry = VpnNlriEntry {
                    path_id: 0,
                    nlri: shape.vpn(family, index),
                };
                assert_eq!(inventory.vpn_index(&entry).unwrap(), (family, index));
                entry.path_id = 1;
                assert!(inventory.vpn_index(&entry).is_err());
            }
        }
        assert_ne!(
            shape.vpn(0, 0).route_distinguisher,
            shape.vpn(0, 1).route_distinguisher
        );
        assert_eq!(shape.vpn(0, 0).prefix, shape.vpn(0, 1).prefix);
    }

    #[test]
    fn recovery_mass_dirty_bitmap_rejects_unknown_duplicate_and_bystander_withdrawal() {
        let mut inventory = Inventory::new(Shape {
            vpn: false,
            counts: [160, 40],
            denied: DENIED,
            batch_size: 80,
        });
        inventory.arm(true);
        assert!(inventory.event(0, 0, None).is_err());
        inventory.present[0][0] = u64::MAX;
        inventory.present_count[0] = 64;
        inventory.event(0, 0, None).unwrap();
        assert!(inventory.event(0, 0, None).is_err());
        assert!(inventory.event(0, DENIED, None).is_err());
        assert!(inventory.event(0, 0, Some(COMMUNITY_GEN_B)).is_err());
        assert!(inventory.event(0, DENIED, Some(u32::MAX)).is_err());
    }

    #[test]
    fn recovery_mass_dirty_prior_replay_never_reverses_a_target_event_or_counts_as_coverage() {
        let shape = Shape {
            vpn: false,
            counts: [160, 40],
            denied: DENIED,
            batch_size: 80,
        };
        let mut inventory = Inventory::new(shape);
        assert!(inventory.event(0, DENIED, Some(COMMUNITY_GEN_B)).is_err());
        inventory.event(0, DENIED, Some(COMMUNITY_GEN_A)).unwrap();
        inventory.event(0, 0, Some(COMMUNITY_GEN_A)).unwrap();
        inventory.arm(true);
        inventory.event(0, DENIED, Some(COMMUNITY_GEN_A)).unwrap();
        assert_eq!(inventory.generation_count, [0, 0]);
        inventory.event(0, DENIED, Some(COMMUNITY_GEN_B)).unwrap();
        assert!(inventory.event(0, DENIED, Some(COMMUNITY_GEN_A)).is_err());
        inventory.event(0, 0, None).unwrap();
        assert!(inventory.event(0, 0, Some(COMMUNITY_GEN_A)).is_err());
        inventory.arm(false);
        assert!(inventory.event(0, 0, Some(COMMUNITY_GEN_B)).is_err());
        inventory.event(0, DENIED, Some(COMMUNITY_GEN_B)).unwrap();
        assert_eq!(inventory.generation_count, [0, 0]);
        inventory.event(0, DENIED, Some(COMMUNITY_GEN_A)).unwrap();
        assert!(inventory.event(0, DENIED, Some(COMMUNITY_GEN_B)).is_err());
    }

    #[test]
    fn recovery_mass_dirty_wire_round_trip_uses_existing_vpn_grammar() {
        let shape = Shape {
            vpn: true,
            counts: [160, 40],
            denied: 0,
            batch_size: 80,
        };
        for family in 0..2 {
            let message = announce(shape, family, 0, 8, false).unwrap();
            let mut bytes = bytes::Bytes::from(encode_message(&message).unwrap());
            let Message::Update(update) = decode_message(&mut bytes, MAX_MESSAGE_LEN).unwrap()
            else {
                panic!("UPDATE expected");
            };
            let parsed = update.parse(true, false, &[]).unwrap();
            let mp = parsed
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    PathAttribute::MpReachNlri(mp) => Some(mp),
                    _ => None,
                })
                .unwrap();
            assert_eq!(mp.vpn_announced.len(), 8);
            assert_eq!(mp.next_hop, next_hop(family));
            for (index, entry) in mp.vpn_announced.iter().enumerate() {
                assert_eq!(entry.nlri, shape.vpn(family, index));
            }
        }
    }
}
