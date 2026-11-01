//! Sans-IO discovery state: the per-interface candidate table, the binding
//! rules of ADR-0142, and the RA/RS transmit schedule of RFC 4861 §6.2.
//!
//! Inputs are validated RAs/RSs, link events, session inputs and the clock;
//! outputs are [`DiscoveryEvent`]s for the neighbor owner and [`Transmit`]s
//! for the socket layer. Nothing here reads a clock or touches a socket.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use super::packet::DropReason;

/// RFC 4861 §6.2.1 `MaxRtrAdvInterval` bounds.
pub const MIN_RA_INTERVAL_SECS: u16 = 4;
pub const MAX_RA_INTERVAL_SECS: u16 = 1800;
pub const DEFAULT_RA_INTERVAL_SECS: u16 = 10;
/// RFC 4861 §6.2.1 floor for `MinRtrAdvInterval`.
const MIN_RTR_ADV_FLOOR: Duration = Duration::from_secs(3);
/// RFC 4861 §10 `MAX_INITIAL_RTR_ADVERT_INTERVAL` / `MAX_INITIAL_RTR_ADVERTISEMENTS`.
const MAX_INITIAL_RTR_ADVERT_INTERVAL: Duration = Duration::from_secs(16);
const MAX_INITIAL_RTR_ADVERTISEMENTS: u8 = 3;
/// RFC 4861 §10 `MAX_RA_DELAY_TIME` / `MIN_DELAY_BETWEEN_RAS` (§6.2.6 RS replies).
const MAX_RA_DELAY_TIME: Duration = Duration::from_millis(500);
const MIN_DELAY_BETWEEN_RAS: Duration = Duration::from_secs(3);
/// ADR-0142: a candidate advertised with Router Lifetime 0 is held this long.
pub const LIFETIME_ZERO_HOLD: Duration = Duration::from_secs(30);
/// Live candidates kept per interface. A link with one BGP peer needs one;
/// the cap bounds the table when a segment floods RAs from many sources.
pub const MAX_CANDIDATES_PER_INTERFACE: usize = 16;

/// Validated `ra_interval_secs` and the RA timing derived from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaTiming {
    max_interval: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "ra_interval_secs {0} is outside {MIN_RA_INTERVAL_SECS}..={MAX_RA_INTERVAL_SECS} (RFC 4861 §6.2.1)"
)]
pub struct RaIntervalOutOfRange(pub u16);

impl RaTiming {
    pub fn new(interval_secs: u16) -> Result<Self, RaIntervalOutOfRange> {
        if (MIN_RA_INTERVAL_SECS..=MAX_RA_INTERVAL_SECS).contains(&interval_secs) {
            Ok(Self {
                max_interval: Duration::from_secs(u64::from(interval_secs)),
            })
        } else {
            Err(RaIntervalOutOfRange(interval_secs))
        }
    }

    /// RFC 4861 `MaxRtrAdvInterval`: the configured interval.
    pub fn max_interval(self) -> Duration {
        self.max_interval
    }

    /// RFC 4861 `MinRtrAdvInterval`: 0.33 × `MaxRtrAdvInterval`, at least 3 s.
    pub fn min_interval(self) -> Duration {
        (self.max_interval * 33 / 100).max(MIN_RTR_ADV_FLOOR)
    }

    /// `AdvDefaultLifetime`: three times the interval (RFC 4861's default ratio).
    pub fn router_lifetime_secs(self) -> u16 {
        // max_interval <= 1800 s, so 3x fits u16 (5400 <= 9000).
        u16::try_from(self.max_interval.as_secs() * 3).unwrap_or(u16::MAX)
    }
}

impl Default for RaTiming {
    fn default() -> Self {
        Self {
            max_interval: Duration::from_secs(u64::from(DEFAULT_RA_INTERVAL_SECS)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiscoveryConfig {
    /// `router_advertisements`: send RAs and the link-up RS. Reception is
    /// always on.
    pub send: bool,
    pub timing: RaTiming,
}

/// Link state as the link monitor reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Up,
    /// Confirmed carrier loss or administrative down.
    Down,
    /// The interface no longer exists.
    Removed,
    /// The monitor cannot read the state. Never treated as carrier loss.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkEvent {
    pub ifindex: u32,
    pub name: String,
    pub state: LinkState,
}

/// A learned TCP endpoint: `address%ifindex`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub address: Ipv6Addr,
    pub ifindex: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    CandidateLearned {
        interface: String,
        address: Ipv6Addr,
    },
    /// Lifetime expiry, or every candidate when the link went down, was
    /// removed, or was recreated with a new ifindex.
    CandidateExpired {
        interface: String,
        address: Ipv6Addr,
    },
    BindingChanged {
        interface: String,
        previous: Option<Endpoint>,
        current: Option<Endpoint>,
    },
    /// A live RA source other than the interface's Established peer, or
    /// failing that its binding: when it is learned, or, for a source
    /// learned before the Established report, when that report arrives. A
    /// source a conflict has named, on either side, is not named again
    /// while it stays a candidate. With no Established peer known, a source
    /// that returns beside a binding a conflict already named it with is
    /// held for the report, which names each held return unless the source
    /// is the peer. It never moves the binding.
    Conflict {
        interface: String,
        bound: Ipv6Addr,
        other: Ipv6Addr,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transmit {
    /// Multicast RA to all-nodes. Lifetime 0 on stop (RFC 4861 §6.2.5).
    RouterAdvertisement {
        ifindex: u32,
        router_lifetime_secs: u16,
    },
    /// Multicast RS to all-routers.
    RouterSolicitation { ifindex: u32 },
}

/// A live RA source.
#[derive(Debug, Clone, Copy)]
struct Candidate {
    expiry: Instant,
    /// A `Conflict` has named it, as `bound` or `other`, or its return was
    /// held for the Established report.
    reported: bool,
}

#[derive(Debug, Default)]
struct Interface {
    ifindex: Option<u32>,
    up: bool,
    /// Confirmed `Down` or `Removed` and no `Up` since: candidate input is
    /// refused, so packets still queued from before the loss cannot rebind.
    confirmed_down: bool,
    /// Changes on every `Up` after confirmed loss or recreation. The socket
    /// layer stamps each packet with the generation it was read under, and
    /// input from an older generation is discarded.
    generation: u64,
    candidates: BTreeMap<Ipv6Addr, Candidate>,
    binding: Option<Endpoint>,
    /// The neighbor's session is Established: discovery must not move the
    /// binding until an explicit session-failed or confirmed-down input.
    established: bool,
    /// Address of the neighbor's Established peer, which an inbound
    /// connection may have taught the owner without any RA: a new source
    /// other than it is a conflict even before discovery has a binding.
    established_peer: Option<Ipv6Addr>,
    /// Each pair of sources a conflict has named (lower address first),
    /// kept while either is a candidate, with the returns of each side that
    /// are held for the Established report. At most
    /// `MAX_CANDIDATES_PER_INTERFACE` pairs per address.
    named_pairs: BTreeMap<(Ipv6Addr, Ipv6Addr), [u32; 2]>,
    next_ra: Option<Instant>,
    last_ra: Option<Instant>,
    initial_ras_left: u8,
}

pub(crate) struct Engine {
    config: DiscoveryConfig,
    interfaces: BTreeMap<String, Interface>,
    rng: u64,
    last_generation: u64,
    pub(crate) events: Vec<DiscoveryEvent>,
    pub(crate) transmits: Vec<Transmit>,
}

impl Engine {
    pub(crate) fn new(config: DiscoveryConfig, seed: u64) -> Self {
        Self {
            config,
            interfaces: BTreeMap::new(),
            rng: seed | 1,
            last_generation: 0,
            events: Vec::new(),
            transmits: Vec::new(),
        }
    }

    /// Begin discovery on `name`. Nothing is received or sent until a link
    /// event supplies its ifindex; the first `Up` sends the link-up RS.
    pub(crate) fn start(&mut self, name: &str) {
        if !self.interfaces.contains_key(name) {
            let generation = self.next_generation();
            self.interfaces.insert(
                name.to_owned(),
                Interface {
                    generation,
                    ..Interface::default()
                },
            );
        }
    }

    fn next_generation(&mut self) -> u64 {
        self.last_generation += 1;
        self.last_generation
    }

    /// End discovery on `name`, sending a final lifetime-0 RA when this
    /// router was advertising there (RFC 4861 §6.2.5).
    pub(crate) fn stop(&mut self, name: &str) {
        if let Some(iface) = self.interfaces.remove(name)
            && let (Some(ifindex), true) = (iface.ifindex, iface.next_ra.is_some())
        {
            self.transmits.push(Transmit::RouterAdvertisement {
                ifindex,
                router_lifetime_secs: 0,
            });
        }
    }

    pub(crate) fn stop_all(&mut self) {
        let names: Vec<String> = self.interfaces.keys().cloned().collect();
        for name in names {
            self.stop(&name);
        }
    }

    /// (name, ifindex, generation) of every started interface whose ifindex
    /// is known and that is not confirmed down: the sockets to keep open.
    pub(crate) fn bound_interfaces(&self) -> impl Iterator<Item = (&str, u32, u64)> {
        self.interfaces
            .iter()
            .filter(|(_, i)| !i.confirmed_down)
            .filter_map(|(name, i)| Some((name.as_str(), i.ifindex?, i.generation)))
    }

    pub(crate) fn on_link(&mut self, event: &LinkEvent, now: Instant) {
        let next_generation = self.last_generation + 1;
        let Some(iface) = self.interfaces.get_mut(&event.name) else {
            return;
        };
        expire(&event.name, iface, now, &mut self.events);
        let recreated = iface.ifindex.is_some_and(|i| i != event.ifindex);
        match event.state {
            // Unknown never clears anything. An Unknown report naming a
            // different ifindex is not trusted to mean a recreation either.
            LinkState::Unknown => {
                if iface.ifindex.is_none() {
                    iface.ifindex = Some(event.ifindex);
                }
            }
            LinkState::Down | LinkState::Removed => {
                clear(&event.name, iface, &mut self.events);
                iface.up = false;
                iface.confirmed_down = true;
                iface.next_ra = None;
                iface.ifindex = (event.state == LinkState::Down).then_some(event.ifindex);
            }
            LinkState::Up => {
                if recreated {
                    clear(&event.name, iface, &mut self.events);
                    iface.up = false;
                }
                if recreated || iface.confirmed_down {
                    iface.confirmed_down = false;
                    iface.generation = next_generation;
                    self.last_generation = next_generation;
                }
                iface.ifindex = Some(event.ifindex);
                if !iface.up {
                    iface.up = true;
                    if self.config.send {
                        self.transmits.push(Transmit::RouterSolicitation {
                            ifindex: event.ifindex,
                        });
                        iface.initial_ras_left = MAX_INITIAL_RTR_ADVERTISEMENTS;
                        iface.next_ra = Some(now);
                    }
                }
            }
        }
    }

    /// A validated RA read on `ifindex` under link `generation`.
    /// `is_own(name, source)` reports whether the source is assigned to the
    /// receiving interface. It is asked for every RA that is not dropped by
    /// the candidate cap, including refreshes of a known candidate: an
    /// address assigned locally after it was learned (a local radvd, say)
    /// stops being a candidate at its next RA, which is then dropped.
    /// `None` means the address list could not be read: the RA is skipped
    /// without learning, refreshing or removing anything.
    pub(crate) fn on_router_advertisement(
        &mut self,
        ifindex: u32,
        generation: u64,
        source: Ipv6Addr,
        router_lifetime_secs: u16,
        now: Instant,
        is_own: impl FnOnce(&str, Ipv6Addr) -> Option<bool>,
    ) -> Result<(), DropReason> {
        let Some((name, iface)) = self
            .interfaces
            .iter_mut()
            .find(|(_, i)| i.ifindex == Some(ifindex))
        else {
            return Ok(());
        };
        // Apply overdue expiry first, so a late refresh cannot revive an
        // expired candidate or keep its binding ahead of the timer.
        expire(name, iface, now, &mut self.events);
        if iface.confirmed_down || iface.generation != generation {
            return Err(DropReason::StaleLink);
        }
        let hold = if router_lifetime_secs == 0 {
            LIFETIME_ZERO_HOLD
        } else {
            Duration::from_secs(u64::from(router_lifetime_secs))
        };
        let known = iface.candidates.contains_key(&source);
        if !known && iface.candidates.len() >= MAX_CANDIDATES_PER_INTERFACE {
            return Err(DropReason::CandidateLimit);
        }
        let Some(own) = is_own(name, source) else {
            return Err(DropReason::AddressInventoryUnavailable);
        };
        if own {
            if known {
                iface.candidates.remove(&source);
                prune_pairs(iface);
                self.events.push(DiscoveryEvent::CandidateExpired {
                    interface: name.clone(),
                    address: source,
                });
                reselect(name, iface, &mut self.events);
            }
            return Err(DropReason::OwnAddress);
        }
        if let Some(candidate) = iface.candidates.get_mut(&source) {
            candidate.expiry = now + hold;
            return Ok(());
        }
        iface.candidates.insert(
            source,
            Candidate {
                expiry: now + hold,
                reported: false,
            },
        );
        self.events.push(DiscoveryEvent::CandidateLearned {
            interface: name.clone(),
            address: source,
        });
        reselect(name, iface, &mut self.events);
        if let Some(bound) = iface
            .established_peer
            .or(iface.binding.map(|binding| binding.address))
            && bound != source
        {
            // With no Established peer known, a source returning beside a
            // binding a conflict already named it with is either the peer
            // itself or that pair's foreign router again. Hold the return:
            // the report names it only if it is not the peer, as an RA after
            // the report would.
            let key = pair(bound, source);
            if iface.established_peer.is_none()
                && let Some(held) = iface.named_pairs.get_mut(&key)
            {
                let side = &mut held[usize::from(source == key.1)];
                *side = side.saturating_add(1);
                if let Some(candidate) = iface.candidates.get_mut(&source) {
                    candidate.reported = true;
                }
                return Ok(());
            }
            for named in [bound, source] {
                if let Some(candidate) = iface.candidates.get_mut(&named) {
                    candidate.reported = true;
                }
            }
            record_pair(&mut iface.named_pairs, bound, source);
            self.events.push(DiscoveryEvent::Conflict {
                interface: name.clone(),
                bound,
                other: source,
            });
        }
        Ok(())
    }

    /// A valid RS on `ifindex`: answer with an RA at the earliest time 3 s
    /// after the previous RA allows, plus a random delay of up to 500 ms
    /// (RFC 4861 §6.2.6).
    pub(crate) fn on_router_solicitation(&mut self, ifindex: u32, generation: u64, now: Instant) {
        let delay = self.random_up_to(MAX_RA_DELAY_TIME);
        let Some((name, iface)) = self
            .interfaces
            .iter_mut()
            .find(|(_, i)| i.ifindex == Some(ifindex) && i.generation == generation)
        else {
            return;
        };
        expire(name, iface, now, &mut self.events);
        let Some(next) = iface.next_ra else {
            return; // not advertising here
        };
        // §6.2.6: the earliest permitted time, then the random delay on top,
        // so rate-limited replies are still jittered.
        let earliest = iface
            .last_ra
            .map_or(now, |last| now.max(last + MIN_DELAY_BETWEEN_RAS));
        iface.next_ra = Some(next.min(earliest + delay));
    }

    /// The neighbor's session with `peer` reached Established: freeze the
    /// binding, and count later sources other than `peer` as conflicts.
    /// The freeze is ignored without a binding: Established means "the bound
    /// peer is Established", and a report queued from a session retired by
    /// carrier loss must not freeze an interface that has nothing bound. The
    /// owner follows such a retirement with `session_failed`, which also
    /// forgets `peer`.
    ///
    /// A live source learned before this report that no conflict has named
    /// is a conflict now: a foreign router whose RA arrived first became the
    /// binding with nothing to compare it with. A conflict already raised
    /// beside it, `peer`'s own RA's included, counted it. So only a first
    /// binding can go uncounted: one that expired before the report with no
    /// conflict, or one named only beside another foreign router, which that
    /// conflict counted instead.
    ///
    /// Each return held before this report is named now unless its source
    /// is `peer`, so the count matches an earlier report's while one of the
    /// pair is still a candidate.
    pub(crate) fn session_established(&mut self, name: &str, peer: Ipv6Addr, now: Instant) {
        let Some(iface) = self.interfaces.get_mut(name) else {
            return;
        };
        expire(name, iface, now, &mut self.events);
        iface.established_peer = Some(peer);
        if iface.binding.is_some() {
            iface.established = true;
        }
        let mut named = Vec::new();
        for (&address, candidate) in &mut iface.candidates {
            if address == peer || candidate.reported {
                continue;
            }
            candidate.reported = true;
            named.push(address);
            self.events.push(DiscoveryEvent::Conflict {
                interface: name.to_owned(),
                bound: peer,
                other: address,
            });
        }
        if !named.is_empty()
            && let Some(candidate) = iface.candidates.get_mut(&peer)
        {
            candidate.reported = true;
        }
        for address in named {
            record_pair(&mut iface.named_pairs, peer, address);
        }
        for (&(low, high), [held_low, held_high]) in &mut iface.named_pairs {
            for (address, held) in [(low, held_low), (high, held_high)] {
                let returns = std::mem::take(held);
                if address == peer {
                    continue;
                }
                for _ in 0..returns {
                    self.events.push(DiscoveryEvent::Conflict {
                        interface: name.to_owned(),
                        bound: peer,
                        other: address,
                    });
                }
            }
        }
    }

    /// The neighbor's session failed (hold timer, BFD, NOTIFICATION, TCP
    /// close). Only now may an expired binding move or be released.
    pub(crate) fn session_failed(&mut self, name: &str, now: Instant) {
        if let Some(iface) = self.interfaces.get_mut(name) {
            iface.established = false;
            iface.established_peer = None;
            expire(name, iface, now, &mut self.events);
            reselect(name, iface, &mut self.events);
        }
    }

    /// Expire candidates and send due RAs.
    pub(crate) fn poll(&mut self, now: Instant) {
        let timing = self.config.timing;
        let names: Vec<String> = self.interfaces.keys().cloned().collect();
        for name in names {
            let mut delay = timing.min_interval()
                + self.random_up_to(timing.max_interval().saturating_sub(timing.min_interval()));
            let iface = self.interfaces.get_mut(&name).expect("key just listed");
            expire(&name, iface, now, &mut self.events);
            if let (Some(due), Some(ifindex)) = (iface.next_ra, iface.ifindex)
                && due <= now
            {
                self.transmits.push(Transmit::RouterAdvertisement {
                    ifindex,
                    router_lifetime_secs: timing.router_lifetime_secs(),
                });
                if iface.initial_ras_left > 0 {
                    iface.initial_ras_left -= 1;
                    delay = delay.min(MAX_INITIAL_RTR_ADVERT_INTERVAL);
                }
                iface.last_ra = Some(now);
                iface.next_ra = Some(now + delay);
            }
        }
    }

    /// The pairs `name` remembers, for the bound tests.
    #[cfg(test)]
    pub(crate) fn named_pairs(&self, name: &str) -> usize {
        self.interfaces[name].named_pairs.len()
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.interfaces
            .values()
            .flat_map(|i| i.candidates.values().map(|c| c.expiry).chain(i.next_ra))
            .min()
    }

    /// Uniform in `0..=max` at millisecond resolution (xorshift64).
    fn random_up_to(&mut self, max: Duration) -> Duration {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        let span = u64::try_from(max.as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(self.rng % span.saturating_add(1))
    }
}

/// The `named_pairs` key of `a` and `b`.
fn pair(a: Ipv6Addr, b: Ipv6Addr) -> (Ipv6Addr, Ipv6Addr) {
    (a.min(b), a.max(b))
}

/// A conflict named `a` and `b`: remember the pair, unless either address
/// already has `MAX_CANDIDATES_PER_INTERFACE` pairs (a later return of that
/// pair is then named at once).
fn record_pair(pairs: &mut BTreeMap<(Ipv6Addr, Ipv6Addr), [u32; 2]>, a: Ipv6Addr, b: Ipv6Addr) {
    let key = pair(a, b);
    if pairs.contains_key(&key) {
        return;
    }
    let full = |address: Ipv6Addr| {
        pairs
            .keys()
            .filter(|(low, high)| *low == address || *high == address)
            .count()
            >= MAX_CANDIDATES_PER_INTERFACE
    };
    if !full(a) && !full(b) {
        pairs.insert(key, [0, 0]);
    }
}

/// Forget the pairs neither of whose sources is still a candidate.
fn prune_pairs(iface: &mut Interface) {
    let candidates = &iface.candidates;
    iface
        .named_pairs
        .retain(|(low, high), _| candidates.contains_key(low) || candidates.contains_key(high));
}

/// Drop candidates whose lifetime has run out by `now` and reselect. Every
/// input applies this first, so the outcome never depends on whether the
/// expiry timer or the input was processed first.
fn expire(name: &str, iface: &mut Interface, now: Instant, events: &mut Vec<DiscoveryEvent>) {
    let before = iface.candidates.len();
    iface.candidates.retain(|address, candidate| {
        let live = candidate.expiry > now;
        if !live {
            events.push(DiscoveryEvent::CandidateExpired {
                interface: name.to_owned(),
                address: *address,
            });
        }
        live
    });
    if iface.candidates.len() != before {
        prune_pairs(iface);
        reselect(name, iface, events);
    }
}

/// ADR-0142 binding rule. While the session is not Established, keep the
/// current binding if its candidate is live, otherwise bind the numerically
/// lowest live candidate (or nothing). While Established, never move.
fn reselect(name: &str, iface: &mut Interface, events: &mut Vec<DiscoveryEvent>) {
    if iface.established {
        return;
    }
    let Some(ifindex) = iface.ifindex else {
        return;
    };
    if iface
        .binding
        .is_some_and(|b| iface.candidates.contains_key(&b.address))
    {
        return;
    }
    let current = iface
        .candidates
        .keys()
        .next()
        .map(|&address| Endpoint { address, ifindex });
    if current != iface.binding {
        events.push(DiscoveryEvent::BindingChanged {
            interface: name.to_owned(),
            previous: iface.binding,
            current,
        });
        iface.binding = current;
    }
}

/// Confirmed carrier loss, removal or recreation: drop every candidate and
/// the binding. The session is torn down by the owner, so it is no longer
/// Established.
fn clear(name: &str, iface: &mut Interface, events: &mut Vec<DiscoveryEvent>) {
    for address in std::mem::take(&mut iface.candidates).into_keys() {
        events.push(DiscoveryEvent::CandidateExpired {
            interface: name.to_owned(),
            address,
        });
    }
    iface.named_pairs.clear();
    iface.established = false;
    iface.established_peer = None;
    if let Some(previous) = iface.binding.take() {
        events.push(DiscoveryEvent::BindingChanged {
            interface: name.to_owned(),
            previous: Some(previous),
            current: None,
        });
    }
}
