use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;

use crate::proto::{GlobalState, HealthResponse, NeighborState};
use crate::tui::data::{DataSnapshot, Freshness, RouteEventEntry};

const MAX_EVENTS: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum View {
    PeerTable,
    PeerDetail(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Address,
    Asn,
    State,
    Uptime,
    RxPfx,
    TxPfx,
    UpdateRate,
    Flaps,
}

impl SortColumn {
    pub fn label(self) -> &'static str {
        match self {
            SortColumn::Address => "Neighbor",
            SortColumn::Asn => "AS",
            SortColumn::State => "State",
            SortColumn::Uptime => "Uptime",
            SortColumn::RxPfx => "Rx Pfx",
            SortColumn::TxPfx => "Tx Pfx",
            SortColumn::UpdateRate => "Upd/s",
            SortColumn::Flaps => "Flaps",
        }
    }

    fn next(self) -> Self {
        match self {
            SortColumn::Address => SortColumn::Asn,
            SortColumn::Asn => SortColumn::State,
            SortColumn::State => SortColumn::Uptime,
            SortColumn::Uptime => SortColumn::RxPfx,
            SortColumn::RxPfx => SortColumn::TxPfx,
            SortColumn::TxPfx => SortColumn::UpdateRate,
            SortColumn::UpdateRate => SortColumn::Flaps,
            SortColumn::Flaps => SortColumn::Address,
        }
    }
}

struct PeerCounters {
    updates_received: u64,
    updates_sent: u64,
}

pub struct PeerRates {
    pub updates_per_sec_rx: f64,
    pub updates_per_sec_tx: f64,
}

pub(crate) fn neighbor_key(neighbor: &NeighborState) -> Option<String> {
    neighbor.config.as_ref().map(|config| {
        if config.interface.is_empty() {
            config.address.clone()
        } else {
            format!("{}%{}", config.address, config.interface)
        }
    })
}

pub struct App {
    pub global: Option<GlobalState>,
    pub global_freshness: Option<Freshness>,
    pub health: Option<HealthResponse>,
    pub health_fresh: bool,
    pub neighbors: Vec<NeighborState>,
    pub neighbors_freshness: Option<Freshness>,
    pub route_events: VecDeque<RouteEventEntry>,
    pub rpki_vrp_count: Option<u64>,
    pub metrics_freshness: Option<Freshness>,

    prev_counters: HashMap<String, PeerCounters>,
    pub peer_rates: HashMap<String, PeerRates>,
    last_rate_calc: Instant,

    pub view: View,
    pub peer_table_state: TableState,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    pub show_help: bool,
    pub show_events: bool,
    pub should_quit: bool,

    pub connected: bool,
    pub last_error: Option<String>,
    pub last_poll: Instant,
}

impl App {
    pub fn new() -> Self {
        Self {
            global: None,
            global_freshness: None,
            health: None,
            health_fresh: false,
            neighbors: Vec::new(),
            neighbors_freshness: None,
            route_events: VecDeque::new(),
            rpki_vrp_count: None,
            metrics_freshness: None,
            prev_counters: HashMap::new(),
            peer_rates: HashMap::new(),
            last_rate_calc: Instant::now(),
            view: View::PeerTable,
            peer_table_state: TableState::default().with_selected(0),
            sort_column: SortColumn::Address,
            sort_ascending: true,
            show_help: false,
            show_events: false,
            should_quit: false,
            connected: false,
            last_error: None,
            last_poll: Instant::now(),
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        if self.show_help {
            self.show_help = false;
            return;
        }

        match self.view {
            View::PeerTable => self.handle_table_key(key),
            View::PeerDetail(_) => self.handle_detail_key(key),
        }
    }

    fn handle_table_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('h') => self.show_help = true,
            KeyCode::Char('e') => self.show_events = !self.show_events,
            KeyCode::Char('s') => self.sort_column = self.sort_column.next(),
            KeyCode::Char('S') => self.sort_ascending = !self.sort_ascending,
            KeyCode::Char('j') | KeyCode::Down => self.select_next(),
            KeyCode::Char('k') | KeyCode::Up => self.select_prev(),
            KeyCode::Enter => {
                if let Some(i) = self.peer_table_state.selected()
                    && let Some(address) = self.neighbors.get(i).and_then(neighbor_key)
                {
                    self.view = View::PeerDetail(address);
                }
            }
            _ => {}
        }
    }

    fn handle_detail_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc | KeyCode::Backspace => self.view = View::PeerTable,
            _ => {}
        }
    }

    fn select_next(&mut self) {
        if self.neighbors.is_empty() {
            return;
        }
        let i = self
            .peer_table_state
            .selected()
            .map(|i| (i + 1).min(self.neighbors.len() - 1))
            .unwrap_or(0);
        self.peer_table_state.select(Some(i));
    }

    fn select_prev(&mut self) {
        let i = self
            .peer_table_state
            .selected()
            .map(|i| i.saturating_sub(1))
            .unwrap_or(0);
        self.peer_table_state.select(Some(i));
    }

    pub fn on_data(&mut self, snapshot: DataSnapshot) {
        self.on_data_at(snapshot, Instant::now());
    }

    fn on_data_at(&mut self, snapshot: DataSnapshot, now: Instant) {
        self.last_poll = now;
        self.health_fresh = snapshot.health_fresh;
        self.neighbors_freshness = Some(snapshot.neighbors_freshness);
        self.global_freshness = Some(snapshot.global_freshness);
        self.metrics_freshness = Some(snapshot.metrics_freshness);

        if snapshot.health_fresh {
            self.health = snapshot.health;
        }
        if let Some(g) = snapshot.global {
            self.global = Some(g);
        }
        self.rpki_vrp_count = snapshot.rpki_vrp_count;

        self.connected = snapshot.error.is_none();
        self.last_error = snapshot.error;

        // A failed neighbor poll carries no new information. Keep the
        // last-good roster, selection, counters, and rate epoch intact so the
        // next fresh sample spans the whole outage.
        if snapshot.neighbors_freshness != Freshness::Fresh {
            return;
        }

        let selected_addr = self
            .peer_table_state
            .selected()
            .and_then(|i| self.neighbors.get(i))
            .and_then(neighbor_key);

        let elapsed = now.duration_since(self.last_rate_calc).as_secs_f64();
        if elapsed > 0.5 {
            for n in &snapshot.neighbors {
                let Some(key) = neighbor_key(n) else {
                    continue;
                };
                if let Some(prev) = self.prev_counters.get(&key) {
                    let rx_delta = n.updates_received.saturating_sub(prev.updates_received);
                    let tx_delta = n.updates_sent.saturating_sub(prev.updates_sent);
                    self.peer_rates.insert(
                        key.clone(),
                        PeerRates {
                            updates_per_sec_rx: rx_delta as f64 / elapsed,
                            updates_per_sec_tx: tx_delta as f64 / elapsed,
                        },
                    );
                }
                self.prev_counters.insert(
                    key,
                    PeerCounters {
                        updates_received: n.updates_received,
                        updates_sent: n.updates_sent,
                    },
                );
            }
            self.last_rate_calc = now;
        }

        let current_keys: HashSet<String> =
            snapshot.neighbors.iter().filter_map(neighbor_key).collect();
        self.prev_counters
            .retain(|key, _| current_keys.contains(key));
        self.peer_rates.retain(|key, _| current_keys.contains(key));

        self.neighbors = snapshot.neighbors;
        self.sort_neighbors();

        if self.neighbors.is_empty() {
            self.peer_table_state.select(None);
            if matches!(self.view, View::PeerDetail(_)) {
                self.view = View::PeerTable;
            }
            return;
        }

        let selected_idx = selected_addr
            .as_deref()
            .and_then(|address| {
                self.neighbors
                    .iter()
                    .position(|neighbor| neighbor_key(neighbor).as_deref() == Some(address))
            })
            .or_else(|| {
                self.peer_table_state
                    .selected()
                    .map(|i| i.min(self.neighbors.len() - 1))
            })
            .unwrap_or(0);
        self.peer_table_state.select(Some(selected_idx));
    }

    pub fn on_route_event(&mut self, event: RouteEventEntry) {
        self.route_events.push_front(event);
        if self.route_events.len() > MAX_EVENTS {
            self.route_events.pop_back();
        }
    }

    fn sort_neighbors(&mut self) {
        let rates = &self.peer_rates;
        let col = self.sort_column;
        let asc = self.sort_ascending;

        self.neighbors.sort_by(|a, b| {
            let cfg_a = a.config.as_ref();
            let cfg_b = b.config.as_ref();
            let ord = match col {
                SortColumn::Address => neighbor_key(a).cmp(&neighbor_key(b)),
                SortColumn::Asn => {
                    let asn_a = cfg_a.map(|c| c.remote_asn).unwrap_or(0);
                    let asn_b = cfg_b.map(|c| c.remote_asn).unwrap_or(0);
                    asn_a.cmp(&asn_b)
                }
                SortColumn::State => a.state.cmp(&b.state),
                SortColumn::Uptime => a.uptime_seconds.cmp(&b.uptime_seconds),
                SortColumn::RxPfx => a.prefixes_received.cmp(&b.prefixes_received),
                SortColumn::TxPfx => a.prefixes_sent.cmp(&b.prefixes_sent),
                SortColumn::UpdateRate => {
                    let rate_a = rates
                        .get(neighbor_key(a).as_deref().unwrap_or(""))
                        .map(|r| r.updates_per_sec_rx)
                        .unwrap_or(0.0);
                    let rate_b = rates
                        .get(neighbor_key(b).as_deref().unwrap_or(""))
                        .map(|r| r.updates_per_sec_rx)
                        .unwrap_or(0.0);
                    rate_a
                        .partial_cmp(&rate_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                }
                SortColumn::Flaps => a.flap_count.cmp(&b.flap_count),
            };
            if asc { ord } else { ord.reverse() }
        });
    }

    pub fn peer_update_rate(&self, addr: &str) -> f64 {
        self.peer_rates
            .get(addr)
            .map(|r| r.updates_per_sec_rx + r.updates_per_sec_tx)
            .unwrap_or(0.0)
    }

    pub fn neighbor(&self, key: &str) -> Option<&NeighborState> {
        self.neighbors
            .iter()
            .find(|neighbor| neighbor_key(neighbor).as_deref() == Some(key))
    }

    pub fn route_events_visible(&self) -> bool {
        self.show_events && matches!(&self.view, View::PeerTable)
    }

    pub fn established_count(&self) -> usize {
        // Excludes stale peers — `state == 6` on a stale snapshot is the
        // placeholder Idle override (see `output::format_state_with_stale`),
        // so a stalled session would otherwise look Established to the
        // header bar even when the daemon couldn't read fresh state.
        self.neighbors
            .iter()
            .filter(|n| n.state == 6 && !n.stale)
            .count()
    }

    pub fn total_routes(&self) -> u32 {
        self.health.as_ref().map(|h| h.total_routes).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{NeighborConfig, NeighborState};

    fn neighbor(address: &str, uptime_seconds: u64) -> NeighborState {
        NeighborState {
            config: Some(NeighborConfig {
                address: address.to_string(),
                interface: String::new(),
                remote_asn: 64512,
                description: String::new(),
                hold_time: 90,
                max_prefixes: 0,
                families: vec!["ipv4_unicast".into()],
                remove_private_as: String::new(),
                peer_group: String::new(),
                ..Default::default()
            }),
            state: 6,
            uptime_seconds,
            prefixes_received: 0,
            prefixes_sent: 0,
            updates_received: 0,
            updates_sent: 0,
            notifications_received: 0,
            notifications_sent: 0,
            flap_count: 0,
            last_error: String::new(),
            is_dynamic: false,
            stale: false,
            ..Default::default()
        }
    }

    fn scoped_neighbor(address: &str, interface: &str, uptime_seconds: u64) -> NeighborState {
        let mut neighbor = neighbor(address, uptime_seconds);
        neighbor.config.as_mut().unwrap().interface = interface.to_string();
        neighbor
    }

    fn snapshot(neighbors: Vec<NeighborState>) -> DataSnapshot {
        DataSnapshot {
            global: None,
            global_freshness: Freshness::Unavailable,
            health: Some(HealthResponse {
                healthy: true,
                uptime_seconds: 1,
                active_peers: neighbors.len() as u32,
                total_routes: 0,
                daemon_version: String::new(),
            }),
            health_fresh: true,
            neighbors,
            neighbors_freshness: Freshness::Fresh,
            rpki_vrp_count: None,
            metrics_freshness: Freshness::Unavailable,
            error: None,
        }
    }

    fn counters(mut neighbor: NeighborState, received: u64, sent: u64) -> NeighborState {
        neighbor.updates_received = received;
        neighbor.updates_sent = sent;
        neighbor
    }

    /// Red proof: ignoring the active view leaves hidden event streaming armed.
    #[test]
    fn detail_view_tracks_peer_and_suspends_events() {
        let mut app = App::new();
        app.sort_column = SortColumn::Uptime;
        app.sort_ascending = false;

        app.on_data(snapshot(vec![
            neighbor("198.51.100.1", 100),
            neighbor("198.51.100.2", 50),
        ]));
        app.show_events = true;
        assert!(app.route_events_visible());
        app.view = View::PeerDetail("198.51.100.1".into());
        assert!(!app.route_events_visible());

        app.on_data(snapshot(vec![
            neighbor("198.51.100.1", 10),
            neighbor("198.51.100.2", 200),
        ]));

        assert_eq!(app.view, View::PeerDetail("198.51.100.1".into()));
    }

    #[test]
    fn selection_tracks_same_peer_after_resort() {
        let mut app = App::new();
        app.sort_column = SortColumn::Uptime;
        app.sort_ascending = false;

        app.on_data(snapshot(vec![
            neighbor("198.51.100.1", 100),
            neighbor("198.51.100.2", 50),
        ]));
        app.peer_table_state.select(Some(0));

        app.on_data(snapshot(vec![
            neighbor("198.51.100.1", 10),
            neighbor("198.51.100.2", 200),
        ]));

        let selected = app
            .peer_table_state
            .selected()
            .and_then(|i| app.neighbors.get(i))
            .and_then(|neighbor| neighbor.config.as_ref())
            .map(|config| config.address.as_str());
        assert_eq!(selected, Some("198.51.100.1"));
    }

    #[test]
    fn selection_tracks_scoped_peer_after_resort() {
        let mut app = App::new();
        app.sort_column = SortColumn::Uptime;
        app.sort_ascending = false;

        app.on_data(snapshot(vec![
            scoped_neighbor("fe80::1", "eth0", 100),
            scoped_neighbor("fe80::1", "eth1", 50),
        ]));
        app.peer_table_state.select(Some(0));

        app.on_data(snapshot(vec![
            scoped_neighbor("fe80::1", "eth0", 10),
            scoped_neighbor("fe80::1", "eth1", 200),
        ]));

        let selected = app
            .peer_table_state
            .selected()
            .and_then(|i| app.neighbors.get(i))
            .and_then(|neighbor| neighbor.config.as_ref())
            .map(|config| config.interface.as_str());
        assert_eq!(selected, Some("eth0"));
    }

    /// Red proof: bare-address lookup collapses scoped peers and detail keys.
    #[test]
    fn scoped_peers_keep_distinct_rates_and_detail_identity() {
        let mut app = App::new();
        let start = Instant::now();
        app.last_rate_calc = start;

        app.on_data_at(
            snapshot(vec![
                counters(scoped_neighbor("fe80::1", "eth0", 1), 10, 5),
                counters(scoped_neighbor("fe80::1", "eth1", 1), 20, 10),
            ]),
            start + std::time::Duration::from_secs(1),
        );
        app.on_data_at(
            snapshot(vec![
                counters(scoped_neighbor("fe80::1", "eth0", 2), 14, 7),
                counters(scoped_neighbor("fe80::1", "eth1", 2), 28, 14),
            ]),
            start + std::time::Duration::from_secs(2),
        );

        assert_eq!(app.peer_update_rate("fe80::1%eth0"), 6.0);
        assert_eq!(app.peer_update_rate("fe80::1%eth1"), 12.0);
        assert!(app.neighbor("fe80::1%eth0").is_some());
        assert!(app.neighbor("fe80::1%eth1").is_some());
    }

    /// Red proof: removing the freshness guard replaces the roster and rate epoch.
    #[test]
    fn stale_roster_retains_selection_and_rate_epoch() {
        let mut app = App::new();
        let start = Instant::now();
        app.last_rate_calc = start;
        app.on_data_at(
            snapshot(vec![counters(neighbor("198.51.100.1", 1), 10, 0)]),
            start + std::time::Duration::from_secs(1),
        );
        app.peer_table_state.select(Some(0));

        let mut failed = snapshot(Vec::new());
        failed.neighbors_freshness = Freshness::Stale;
        failed.error = Some("transient neighbor-list failure".into());
        app.on_data_at(failed, start + std::time::Duration::from_secs(2));

        assert_eq!(app.neighbors.len(), 1);
        assert_eq!(app.peer_table_state.selected(), Some(0));

        app.on_data_at(
            snapshot(vec![counters(neighbor("198.51.100.1", 3), 30, 0)]),
            start + std::time::Duration::from_secs(3),
        );
        assert_eq!(app.peer_update_rate("198.51.100.1"), 10.0);
    }

    /// Red proof: removing fresh-roster pruning retains both departed-peer maps.
    #[test]
    fn fresh_roster_prunes_departed_peer_state() {
        let mut app = App::new();
        let start = Instant::now();
        app.last_rate_calc = start;
        app.on_data_at(
            snapshot(vec![
                counters(neighbor("198.51.100.1", 1), 10, 0),
                counters(neighbor("198.51.100.2", 1), 10, 0),
            ]),
            start + std::time::Duration::from_secs(1),
        );
        app.on_data_at(
            snapshot(vec![
                counters(neighbor("198.51.100.1", 2), 20, 0),
                counters(neighbor("198.51.100.2", 2), 20, 0),
            ]),
            start + std::time::Duration::from_secs(2),
        );
        app.on_data_at(
            snapshot(vec![counters(neighbor("198.51.100.1", 3), 30, 0)]),
            start + std::time::Duration::from_secs(3),
        );

        assert!(app.prev_counters.contains_key("198.51.100.1"));
        assert!(app.peer_rates.contains_key("198.51.100.1"));
        assert!(!app.prev_counters.contains_key("198.51.100.2"));
        assert!(!app.peer_rates.contains_key("198.51.100.2"));
    }
}
