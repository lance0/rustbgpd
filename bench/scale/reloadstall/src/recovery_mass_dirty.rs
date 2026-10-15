//! Real-daemon recovery qualification. Python owns triggers and the frozen campaign.

use super::*;
use rustbgpd_wire::{MplsLabelEntry, RouteDistinguisher, VpnNlri, VpnNlriEntry, VpnPrefix};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::oneshot;

const LOCAL_AS: u32 = 64512;
const SOURCE_AS: u32 = 64500;
const DENIED: usize = 4;
const RDS: [RouteDistinguisher; 2] = [
    RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
    RouteDistinguisher([0, 2, 0, 0, 0xfd, 0xe8, 0, 100]),
];
const CELL_DEADLINE: Duration = Duration::from_secs(1800);

#[derive(Clone, Copy)]
struct Shape {
    vpn: bool,
    counts: [usize; 2],
    denied: usize,
}

impl Shape {
    fn new(profile: &str, correctness: bool, pressure: bool) -> Result<Self, String> {
        Ok(Self {
            vpn: match profile {
                "full-uc" => false,
                "full-vpn" => true,
                _ => return Err("profile must be full-uc or full-vpn".into()),
            },
            counts: if correctness {
                [160, 40]
            } else {
                [1_000_000, 230_000]
            },
            denied: if pressure { DENIED } else { 0 },
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

fn attributes() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![SOURCE_AS])],
        }),
        PathAttribute::LocalPref(100),
    ]
}

fn announce(shape: Shape, family: usize, start: usize, end: usize) -> Result<Message, String> {
    let mut attrs = attributes();
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
        let mut expected = if has_announcements {
            attributes()
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
            self.event(family, index, Some(marker))?;
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
                            self.event(f, index, Some(marker))?;
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
                            self.event(f, index, Some(marker))?;
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
    let (stream, _, _) = establish_stream_with_retry(
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
        stub_addr(index),
        &bytes,
        &keepalive,
        CONNECT_WINDOW,
        &shape.families(),
    )
    .await?;
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

async fn readiness_watch(
    metrics: SocketAddr,
    mut stop: oneshot::Receiver<()>,
    correctness: bool,
) -> Result<u64, String> {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut samples = 0;
    loop {
        tokio::select! {
            _ = &mut stop => return Ok(samples),
            _ = tick.tick() => {
                let started = Instant::now();
                // Reuse the HTTP validation and retain the existing client deadline.
                fetch_http(metrics, "/readyz", started + READINESS_DEADLINE).await?;
                let elapsed = started.elapsed();
                if elapsed > READINESS_DEADLINE { return Err("late readiness success".into()); }
                let seconds = if correctness { "null".into() } else { elapsed.as_secs_f64().to_string() };
                println!("mass_dirty_readiness {{\"status\":200,\"deadline_ms\":250,\"elapsed_seconds\":{seconds}}}");
                samples += 1;
            }
        }
    }
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
    let shape = Shape::new(value("--profile")?, correctness, pressure)?;
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
    let (updates, mut outgoing) = mpsc::channel::<Message>(8);
    let source_live = Arc::new(AtomicBool::new(true));
    let source_write_status = source_live.clone();
    tokio::spawn(async move {
        let bytes = encode_message(&Message::Keepalive).unwrap();
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            let result = tokio::select! {
                _ = tick.tick() => source_writer.write_all(&bytes).await,
                message = outgoing.recv() => {
                    let Some(message) = message else { return; };
                    match encode_message(&message) {
                        Ok(bytes) => source_writer.write_all(&bytes).await,
                        Err(_) => { source_write_status.store(false, Ordering::Release); return; }
                    }
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
    for family in 0..2 {
        for start in (0..shape.counts[family]).step_by(80) {
            updates
                .send(announce(
                    shape,
                    family,
                    start,
                    (start + 80).min(shape.counts[family]),
                )?)
                .await
                .map_err(|_| "source writer ended")?;
        }
    }
    wait_for(&receivers, |receiver| {
        receiver.inventory.lock().unwrap().complete()
    })
    .await?;
    terminal_state(&receivers, &source_live)?;
    println!(
        "mass_dirty_ready {{\"receivers\":{count},\"family_keys\":[{},{}],\"bitmap_bytes\":{},\"correctness_only\":{correctness}}}",
        shape.counts[0],
        shape.counts[1],
        count as usize
            * shape
                .counts
                .map(|n| n.div_ceil(64) * 8 * 3)
                .iter()
                .sum::<usize>()
    );
    let (stop, stopped) = oneshot::channel();
    let readiness = tokio::spawn(readiness_watch(metrics, stopped, correctness));
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
    stop.send(()).map_err(|()| "readiness stopped early")?;
    let samples = readiness.await.map_err(|error| error.to_string())??;
    if samples == 0 {
        return Err("no readiness samples".into());
    }
    // The controller may retain the final fold while sampling ownership/memory.
    // Recheck actual reader errors, continuity and inventory at its finish boundary.
    terminal_state(&receivers, &source_live)?;
    println!(
        "mass_dirty_exit {{\"readiness_samples\":{samples},\"readiness_deadline_ms\":250,\"status\":\"PASS\"}}"
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

    fn reflected(shape: Shape, family: usize, extras: Vec<PathAttribute>) -> Message {
        let Message::Update(update) = announce(shape, family, 0, shape.counts[family]).unwrap()
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
        let shape = Shape::new("full-vpn", true, false).unwrap();
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
        let mut inventory = Inventory::new(Shape::new("full-uc", true, true).unwrap());
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
        let shape = Shape::new("full-uc", true, true).unwrap();
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
        let shape = Shape::new("full-vpn", true, false).unwrap();
        for family in 0..2 {
            let message = announce(shape, family, 0, 8).unwrap();
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
