use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;

use crate::proto::{
    ExplainAdvertisedRouteResponse, GlobalState, HealthResponse, ListRoutesResponse, NeighborState,
};
use crate::tui::data::{
    DataSnapshot, Freshness, RibQueryError, RibQueryIdentity, RibQueryKind, RibQueryResponse,
    RibQueryResult, RouteEventEntry, RouteEventUpdate,
};

const MAX_EVENTS: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum View {
    PeerTable,
    PeerDetail(String),
    BestRib(String),
    AdvertisedExplain(String),
}

#[derive(Debug)]
pub enum RibPageState {
    Loading,
    Ready(ListRoutesResponse),
    Error(String),
}

#[derive(Debug)]
pub enum ExplainState {
    Loading,
    Ready(Box<ExplainAdvertisedRouteResponse>),
    Error(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RibIntent {
    Query {
        view_id: u64,
        peer_address: String,
        query: RibQueryKind,
    },
    Cancel,
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
    pub dynamic_range_count: Option<usize>,
    pub dynamic_ranges_freshness: Option<Freshness>,
    pub route_events: VecDeque<RouteEventEntry>,
    pub route_event_stream_status: Option<String>,
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
    pub detail_scroll: usize,
    pub detail_max_scroll: usize,
    pub detail_page_height: usize,
    pub view_id: u64,
    pub rib_page: Option<RibPageState>,
    pub rib_page_token: String,
    pub rib_previous_tokens: Vec<String>,
    pub rib_table_state: TableState,
    pub active_rib_query: Option<RibQueryIdentity>,
    pub explain: Option<ExplainState>,
    pub explain_scroll: usize,
    pub explain_max_scroll: usize,
    pub explain_page_height: usize,
    rib_intents: VecDeque<RibIntent>,
    aborted_reset_used: bool,

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
            dynamic_range_count: None,
            dynamic_ranges_freshness: None,
            route_events: VecDeque::new(),
            route_event_stream_status: None,
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
            detail_scroll: 0,
            detail_max_scroll: 0,
            detail_page_height: 0,
            view_id: 1,
            rib_page: None,
            rib_page_token: String::new(),
            rib_previous_tokens: Vec::new(),
            rib_table_state: TableState::default(),
            active_rib_query: None,
            explain: None,
            explain_scroll: 0,
            explain_max_scroll: 0,
            explain_page_height: 0,
            rib_intents: VecDeque::new(),
            aborted_reset_used: false,
            connected: false,
            last_error: None,
            last_poll: Instant::now(),
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.cancel_rib();
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
            View::BestRib(_) => self.handle_rib_key(key),
            View::AdvertisedExplain(_) => self.handle_explain_key(key),
        }
    }

    fn handle_table_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => {
                self.cancel_rib();
                self.should_quit = true
            }
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
                    self.reset_detail_scroll();
                    self.view = View::PeerDetail(address);
                }
            }
            _ => {}
        }
    }

    fn handle_detail_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => {
                self.cancel_rib();
                self.should_quit = true
            }
            KeyCode::Esc | KeyCode::Backspace => self.return_to_table(),
            KeyCode::Char('r') => {
                if let View::PeerDetail(peer) = self.view.clone() {
                    self.open_best_rib(peer);
                }
            }
            KeyCode::Char('j') | KeyCode::Down => self.scroll_detail_by(1),
            KeyCode::Char('k') | KeyCode::Up => self.scroll_detail_up(1),
            KeyCode::PageDown => self.scroll_detail_by(self.detail_page_height.max(1)),
            KeyCode::PageUp => self.scroll_detail_up(self.detail_page_height.max(1)),
            KeyCode::Home => self.detail_scroll = 0,
            KeyCode::End => self.detail_scroll = self.detail_max_scroll,
            _ => {}
        }
    }

    fn next_view_id(&mut self) -> u64 {
        self.view_id = self.view_id.wrapping_add(1).max(1);
        self.view_id
    }

    fn queue_query(&mut self, peer_address: String, query: RibQueryKind) {
        self.active_rib_query = None;
        self.rib_intents.push_back(RibIntent::Query {
            view_id: self.view_id,
            peer_address,
            query,
        });
    }

    fn open_best_rib(&mut self, peer: String) {
        self.next_view_id();
        self.view = View::BestRib(peer.clone());
        self.rib_page_token.clear();
        self.rib_previous_tokens.clear();
        self.rib_table_state.select(None);
        self.rib_page = Some(RibPageState::Loading);
        self.aborted_reset_used = false;
        self.queue_query(
            peer,
            RibQueryKind::BestPage {
                page_token: String::new(),
            },
        );
    }

    fn request_page(&mut self, peer: String, token: String) {
        self.rib_page = Some(RibPageState::Loading);
        self.queue_query(peer, RibQueryKind::BestPage { page_token: token });
    }

    fn handle_rib_key(&mut self, key: KeyEvent) {
        let peer = match &self.view {
            View::BestRib(peer) => peer.clone(),
            _ => return,
        };
        match key.code {
            KeyCode::Char('q') => {
                self.cancel_rib();
                self.should_quit = true;
            }
            KeyCode::Esc | KeyCode::Backspace => {
                self.cancel_rib();
                self.view = View::PeerDetail(peer);
            }
            KeyCode::Char('j') | KeyCode::Down => self.select_next_route(),
            KeyCode::Char('k') | KeyCode::Up => self.select_prev_route(),
            KeyCode::Char('n') => {
                if let Some(RibPageState::Ready(page)) = &self.rib_page
                    && !page.next_page_token.is_empty()
                {
                    self.request_page(peer, page.next_page_token.clone());
                }
            }
            KeyCode::Char('p') => {
                if let Some(token) = self.rib_previous_tokens.last().cloned() {
                    self.request_page(peer, token);
                }
            }
            KeyCode::Enter => {
                let selected = self.rib_table_state.selected();
                let route = match (&self.rib_page, selected) {
                    (Some(RibPageState::Ready(page)), Some(i)) => page.routes.get(i),
                    _ => None,
                };
                if let Some(route) = route {
                    let prefix = route.prefix.clone();
                    let prefix_length = route.prefix_length;
                    self.next_view_id();
                    self.view = View::AdvertisedExplain(peer.clone());
                    self.explain = Some(ExplainState::Loading);
                    self.explain_scroll = 0;
                    self.queue_query(
                        peer,
                        RibQueryKind::ExplainAdvertised {
                            prefix,
                            prefix_length,
                        },
                    );
                }
            }
            _ => {}
        }
    }

    fn handle_explain_key(&mut self, key: KeyEvent) {
        let peer = match &self.view {
            View::AdvertisedExplain(peer) => peer.clone(),
            _ => return,
        };
        match key.code {
            KeyCode::Char('q') => {
                self.cancel_rib();
                self.should_quit = true;
            }
            KeyCode::Esc | KeyCode::Backspace => {
                self.cancel_rib();
                self.view = View::BestRib(peer);
                self.explain = None;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.explain_scroll = self
                    .explain_scroll
                    .saturating_add(1)
                    .min(self.explain_max_scroll)
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.explain_scroll = self.explain_scroll.saturating_sub(1)
            }
            KeyCode::PageDown => {
                self.explain_scroll = self
                    .explain_scroll
                    .saturating_add(self.explain_page_height.max(1))
                    .min(self.explain_max_scroll)
            }
            KeyCode::PageUp => {
                self.explain_scroll = self
                    .explain_scroll
                    .saturating_sub(self.explain_page_height.max(1))
            }
            KeyCode::Home => self.explain_scroll = 0,
            KeyCode::End => self.explain_scroll = self.explain_max_scroll,
            _ => {}
        }
    }

    fn route_count(&self) -> usize {
        match &self.rib_page {
            Some(RibPageState::Ready(p)) => p.routes.len(),
            _ => 0,
        }
    }
    fn select_next_route(&mut self) {
        let n = self.route_count();
        if n > 0 {
            let i = self
                .rib_table_state
                .selected()
                .map_or(0, |i| (i + 1).min(n - 1));
            self.rib_table_state.select(Some(i));
        }
    }
    fn select_prev_route(&mut self) {
        if self.route_count() > 0 {
            self.rib_table_state.select(Some(
                self.rib_table_state
                    .selected()
                    .unwrap_or(0)
                    .saturating_sub(1),
            ));
        }
    }

    pub(crate) fn take_rib_intent(&mut self) -> Option<RibIntent> {
        self.rib_intents.pop_front()
    }
    pub(crate) fn record_rib_request(&mut self, identity: RibQueryIdentity) {
        self.active_rib_query = Some(identity);
    }
    pub(crate) fn rib_unavailable(&mut self, message: impl Into<String>) {
        let text = format!("RIB unavailable: {}", message.into());
        match self.view {
            View::AdvertisedExplain(_) => self.explain = Some(ExplainState::Error(text)),
            _ => self.rib_page = Some(RibPageState::Error(text)),
        }
        self.active_rib_query = None;
    }
    fn cancel_rib(&mut self) {
        if self.active_rib_query.take().is_some()
            || matches!(self.view, View::BestRib(_) | View::AdvertisedExplain(_))
        {
            self.rib_intents.push_back(RibIntent::Cancel);
        }
    }

    pub(crate) fn on_rib_result(&mut self, result: RibQueryResult) {
        let Some(active) = self.active_rib_query.take() else {
            return;
        };
        if result.identity != active
            || result.identity.request_id != active.request_id
            || result.identity.view_id != self.view_id
        {
            self.active_rib_query = Some(active);
            return;
        }
        let expected_view = match (&self.view, &active.query) {
            (View::BestRib(peer), RibQueryKind::BestPage { .. })
            | (View::AdvertisedExplain(peer), RibQueryKind::ExplainAdvertised { .. }) => {
                peer == &active.peer_address
            }
            _ => false,
        };
        if !expected_view {
            self.active_rib_query = Some(active);
            return;
        }
        match result.result {
            Ok(RibQueryResponse::BestPage(page)) => {
                let RibQueryKind::BestPage { page_token } = active.query else {
                    return;
                };
                if page_token != self.rib_page_token {
                    if self.rib_previous_tokens.last() == Some(&page_token) {
                        self.rib_previous_tokens.pop();
                    } else {
                        self.rib_previous_tokens.push(self.rib_page_token.clone());
                    }
                    self.rib_page_token = page_token;
                }
                self.rib_table_state
                    .select((!page.routes.is_empty()).then_some(0));
                self.rib_page = Some(RibPageState::Ready(page));
            }
            Ok(RibQueryResponse::ExplainAdvertised(explain)) => {
                self.explain = Some(ExplainState::Ready(explain))
            }
            Err(error)
                if error.code == tonic::Code::Aborted
                    && matches!(active.query, RibQueryKind::BestPage { ref page_token } if !page_token.is_empty())
                    && !self.aborted_reset_used =>
            {
                self.aborted_reset_used = true;
                self.rib_previous_tokens.clear();
                self.rib_page_token.clear();
                self.request_page(active.peer_address, String::new());
            }
            Err(error) => {
                let text = format_rib_error(&error);
                match active.query {
                    RibQueryKind::ExplainAdvertised { .. } => {
                        self.explain = Some(ExplainState::Error(text))
                    }
                    _ => self.rib_page = Some(RibPageState::Error(text)),
                }
            }
        }
    }

    pub(crate) fn set_explain_layout(&mut self, rows: usize, page: usize) {
        self.explain_page_height = page;
        self.explain_max_scroll = rows.saturating_sub(page);
        self.explain_scroll = self.explain_scroll.min(self.explain_max_scroll);
    }

    fn scroll_detail_by(&mut self, rows: usize) {
        self.detail_scroll = self
            .detail_scroll
            .saturating_add(rows)
            .min(self.detail_max_scroll);
    }

    fn scroll_detail_up(&mut self, rows: usize) {
        self.detail_scroll = self.detail_scroll.saturating_sub(rows);
    }

    fn reset_detail_scroll(&mut self) {
        self.detail_scroll = 0;
        self.detail_max_scroll = 0;
        self.detail_page_height = 0;
    }

    pub(crate) fn return_to_table(&mut self) {
        self.cancel_rib();
        self.view = View::PeerTable;
        self.reset_detail_scroll();
    }

    pub(crate) fn set_detail_layout(&mut self, logical_rows: usize, page_height: usize) {
        self.detail_page_height = page_height;
        self.detail_max_scroll = logical_rows
            .saturating_sub(page_height)
            .min(usize::from(u16::MAX));
        self.detail_scroll = self.detail_scroll.min(self.detail_max_scroll);
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
        self.dynamic_range_count = snapshot.dynamic_range_count;
        self.dynamic_ranges_freshness = Some(snapshot.dynamic_ranges_freshness);
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
            if !matches!(self.view, View::PeerTable) {
                self.return_to_table();
            }
            return;
        }

        let viewed_peer = match &self.view {
            View::PeerDetail(peer) | View::BestRib(peer) | View::AdvertisedExplain(peer) => {
                Some(peer)
            }
            View::PeerTable => None,
        };
        if viewed_peer.is_some_and(|peer| !current_keys.contains(peer)) {
            self.return_to_table();
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

    pub fn on_route_event(&mut self, update: RouteEventUpdate) {
        match update {
            RouteEventUpdate::Event(event) => {
                self.route_events.push_front(event);
                if self.route_events.len() > MAX_EVENTS {
                    self.route_events.pop_back();
                }
            }
            RouteEventUpdate::StreamStatus(status) => {
                self.route_event_stream_status = status;
            }
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

fn format_rib_error(error: &RibQueryError) -> String {
    let code = match error.code {
        tonic::Code::Ok => "OK",
        tonic::Code::Cancelled => "CANCELLED",
        tonic::Code::Unknown => "UNKNOWN",
        tonic::Code::InvalidArgument => "INVALID_ARGUMENT",
        tonic::Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        tonic::Code::NotFound => "NOT_FOUND",
        tonic::Code::AlreadyExists => "ALREADY_EXISTS",
        tonic::Code::PermissionDenied => "PERMISSION_DENIED",
        tonic::Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        tonic::Code::FailedPrecondition => "FAILED_PRECONDITION",
        tonic::Code::Aborted => "ABORTED",
        tonic::Code::OutOfRange => "OUT_OF_RANGE",
        tonic::Code::Unimplemented => "UNIMPLEMENTED",
        tonic::Code::Internal => "INTERNAL",
        tonic::Code::Unavailable => "UNAVAILABLE",
        tonic::Code::DataLoss => "DATA_LOSS",
        tonic::Code::Unauthenticated => "UNAUTHENTICATED",
    };
    match error.code {
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => {
            format!("Authorization failed ({code}): {}", error.message)
        }
        tonic::Code::Unavailable => format!("RIB unavailable: {}", error.message),
        tonic::Code::Aborted => format!("RIB snapshot expired: {}", error.message),
        _ => format!("RIB query failed ({code}): {}", error.message),
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
            dynamic_range_count: Some(0),
            dynamic_ranges_freshness: Freshness::Fresh,
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

    /// Red proof: storing stream status in the bounded event deque (or clearing
    /// it while evicting rows) loses the error after 101 events.
    #[test]
    fn primary_stream_error_survives_event_deque_eviction() {
        let mut app = App::new();
        let status = "route event stream error: primary unavailable; retrying";
        app.on_route_event(RouteEventUpdate::StreamStatus(Some(status.into())));
        for index in 0..=MAX_EVENTS {
            app.on_route_event(RouteEventUpdate::Event(RouteEventEntry {
                kind: crate::tui::data::RouteEventKind::Route,
                timestamp: index.to_string(),
                event_type: "added".into(),
                prefix: "203.0.113.0/24".into(),
                peer_address: "192.0.2.1".into(),
                previous_peer_address: String::new(),
                target_peer_address: String::new(),
                reason: String::new(),
                path_id: 0,
                missed_count: 0,
            }));
        }

        assert_eq!(app.route_events.len(), MAX_EVENTS);
        assert_eq!(app.route_event_stream_status.as_deref(), Some(status));
        app.on_route_event(RouteEventUpdate::StreamStatus(None));
        assert!(app.route_event_stream_status.is_none());
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

    /// Red proof: moving range-state updates below the freshness guard leaves
    /// an empty retained roster showing the prior range posture.
    #[test]
    fn stale_roster_snapshot_still_updates_dynamic_range_posture() {
        let mut app = App::new();
        let mut data = snapshot(Vec::new());
        data.neighbors_freshness = Freshness::Stale;
        data.dynamic_range_count = Some(3);
        data.dynamic_ranges_freshness = Freshness::Stale;

        app.on_data(data);

        assert_eq!(app.dynamic_range_count, Some(3));
        assert_eq!(app.dynamic_ranges_freshness, Some(Freshness::Stale));
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

    /// Mutation receipt: changing the production `PageDown` delta from the
    /// reported page height to one row makes the first page assertion fail
    /// while the test still compiles.
    #[test]
    fn detail_scroll_keys_clamp_and_all_detail_exits_reset() {
        let mut app = App::new();
        app.on_data(snapshot(vec![
            neighbor("198.51.100.1", 10),
            neighbor("198.51.100.2", 20),
        ]));
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.view, View::PeerDetail("198.51.100.1".into()));

        app.set_detail_layout(30, 5);
        app.on_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.detail_scroll, 5);
        app.on_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.detail_scroll, 7);
        app.on_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.detail_scroll, 5);
        app.on_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert_eq!(app.detail_scroll, 0);
        app.on_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        assert_eq!(app.detail_scroll, 25);
        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.detail_scroll, 25);
        app.on_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.detail_scroll, 0);

        app.on_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        app.set_detail_layout(4, 5);
        assert_eq!(app.detail_max_scroll, 0);
        assert_eq!(app.detail_scroll, 0, "content shrink clamps the offset");

        app.set_detail_layout(30, 5);
        app.on_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.view, View::PeerTable);
        assert_eq!(
            (
                app.detail_scroll,
                app.detail_max_scroll,
                app.detail_page_height
            ),
            (0, 0, 0)
        );

        app.detail_scroll = 9;
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.detail_scroll, 0, "enter starts at the first row");
        app.set_detail_layout(30, 5);
        app.on_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(app.view, View::PeerTable);
        assert_eq!(app.detail_scroll, 0);

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        app.set_detail_layout(30, 5);
        app.on_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        app.on_data(snapshot(vec![neighbor("198.51.100.2", 30)]));
        assert_eq!(app.view, View::PeerTable);
        assert_eq!(app.detail_scroll, 0, "peer disappearance resets detail");
    }

    #[test]
    fn detail_layout_clamps_scroll_to_renderable_offset() {
        let mut app = App::new();
        app.view = View::PeerDetail("198.51.100.1".into());
        app.set_detail_layout(usize::from(u16::MAX) + 100, 1);

        assert_eq!(app.detail_max_scroll, usize::from(u16::MAX));
        app.on_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        assert_eq!(app.detail_scroll, usize::from(u16::MAX));
    }

    fn open_rib(app: &mut App) -> RibQueryIdentity {
        app.on_data(snapshot(vec![neighbor("198.51.100.1", 10)]));
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        let RibIntent::Query {
            view_id,
            peer_address,
            query,
        } = app.take_rib_intent().unwrap()
        else {
            panic!("query")
        };
        assert_eq!(peer_address, "198.51.100.1");
        assert!(view_id > 1);
        assert_eq!(
            query,
            RibQueryKind::BestPage {
                page_token: String::new()
            }
        );
        let identity = RibQueryIdentity {
            request_id: 7,
            view_id,
            peer_address,
            query,
        };
        app.record_rib_request(identity.clone());
        identity
    }

    fn page(prefix: &str, next: &str) -> ListRoutesResponse {
        ListRoutesResponse {
            routes: vec![crate::proto::Route {
                prefix: prefix.into(),
                prefix_length: 24,
                next_hop: "192.0.2.1".into(),
                peer_address: "192.0.2.2".into(),
                ..Default::default()
            }],
            next_page_token: next.into(),
            total_count: 2,
            page_version: None,
        }
    }

    #[test]
    fn rib_scope_paging_selection_and_explain_identity_are_exact() {
        let mut app = App::new();
        let first = open_rib(&mut app);
        app.on_rib_result(RibQueryResult {
            identity: first,
            result: Ok(RibQueryResponse::BestPage(page(
                "203.0.113.0",
                "next\0opaque",
            ))),
        });
        assert_eq!(app.rib_table_state.selected(), Some(0));
        app.on_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        let RibIntent::Query {
            view_id,
            peer_address,
            query,
        } = app.take_rib_intent().unwrap()
        else {
            panic!()
        };
        assert_eq!(
            query,
            RibQueryKind::BestPage {
                page_token: "next\0opaque".into()
            }
        );
        let next = RibQueryIdentity {
            request_id: 8,
            view_id,
            peer_address,
            query,
        };
        app.record_rib_request(next.clone());
        app.on_rib_result(RibQueryResult {
            identity: next,
            result: Ok(RibQueryResponse::BestPage(page("203.0.114.0", ""))),
        });
        assert_eq!(app.rib_previous_tokens, vec![String::new()]);
        assert_eq!(app.rib_page_token, "next\0opaque");
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let RibIntent::Query {
            peer_address,
            query,
            ..
        } = app.take_rib_intent().unwrap()
        else {
            panic!()
        };
        assert_eq!(peer_address, "198.51.100.1");
        assert_eq!(
            query,
            RibQueryKind::ExplainAdvertised {
                prefix: "203.0.114.0".into(),
                prefix_length: 24
            }
        );
        assert!(matches!(app.view, View::AdvertisedExplain(_)));
        assert!(!app.route_events_visible());
    }

    #[test]
    fn stale_results_fail_every_identity_and_view_guard() {
        let mut app = App::new();
        let active = open_rib(&mut app);
        for mutate in 0..5 {
            let mut stale = active.clone();
            match mutate {
                0 => stale.request_id += 1,
                1 => stale.view_id += 1,
                2 => stale.peer_address.push('x'),
                3 => {
                    stale.query = RibQueryKind::BestPage {
                        page_token: "x".into(),
                    }
                }
                _ => app.view = View::PeerDetail(active.peer_address.clone()),
            }
            app.on_rib_result(RibQueryResult {
                identity: stale,
                result: Ok(RibQueryResponse::BestPage(page("203.0.113.0", ""))),
            });
            assert!(matches!(app.rib_page, Some(RibPageState::Loading)));
            assert_eq!(app.active_rib_query, Some(active.clone()));
            app.view = View::BestRib(active.peer_address.clone());
        }
    }

    #[test]
    fn aborted_page_resets_once_and_errors_are_exact() {
        let mut app = App::new();
        let first = open_rib(&mut app);
        app.on_rib_result(RibQueryResult {
            identity: first,
            result: Ok(RibQueryResponse::BestPage(page("203.0.113.0", "opaque"))),
        });
        app.on_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        let RibIntent::Query {
            view_id,
            peer_address,
            query,
        } = app.take_rib_intent().unwrap()
        else {
            panic!()
        };
        let paged = RibQueryIdentity {
            request_id: 8,
            view_id,
            peer_address,
            query,
        };
        app.record_rib_request(paged.clone());
        app.on_rib_result(RibQueryResult {
            identity: paged,
            result: Err(RibQueryError {
                code: tonic::Code::Aborted,
                message: "changed".into(),
            }),
        });
        let RibIntent::Query { query, .. } = app.take_rib_intent().unwrap() else {
            panic!()
        };
        assert_eq!(
            query,
            RibQueryKind::BestPage {
                page_token: String::new()
            }
        );
        assert!(app.rib_previous_tokens.is_empty());
        assert_eq!(
            format_rib_error(&RibQueryError {
                code: tonic::Code::PermissionDenied,
                message: "no".into()
            }),
            "Authorization failed (PERMISSION_DENIED): no"
        );
        assert_eq!(
            format_rib_error(&RibQueryError {
                code: tonic::Code::Unavailable,
                message: "down".into()
            }),
            "RIB unavailable: down"
        );
        assert_eq!(
            format_rib_error(&RibQueryError {
                code: tonic::Code::Aborted,
                message: "old".into()
            }),
            "RIB snapshot expired: old"
        );
    }

    #[test]
    fn rib_departures_cancel_only_on_fresh_roster() {
        let mut app = App::new();
        open_rib(&mut app);
        let mut stale = snapshot(Vec::new());
        stale.neighbors_freshness = Freshness::Stale;
        app.on_data(stale);
        assert!(matches!(app.view, View::BestRib(_)));
        assert!(app.take_rib_intent().is_none());
        app.on_data(snapshot(Vec::new()));
        assert_eq!(app.view, View::PeerTable);
        assert_eq!(app.take_rib_intent(), Some(RibIntent::Cancel));
    }

    #[test]
    fn every_rib_departure_cancels_and_explain_back_retains_page() {
        for key in [
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        ] {
            let mut app = App::new();
            open_rib(&mut app);
            app.on_key(key);
            assert_eq!(app.take_rib_intent(), Some(RibIntent::Cancel));
        }

        let mut app = App::new();
        let first = open_rib(&mut app);
        app.on_rib_result(RibQueryResult {
            identity: first,
            result: Ok(RibQueryResponse::BestPage(page("203.0.113.0", ""))),
        });
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let retained_prefix = match &app.rib_page {
            Some(RibPageState::Ready(page)) => page.routes[0].prefix.clone(),
            _ => panic!(),
        };
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.view, View::BestRib("198.51.100.1".into()));
        assert_eq!(retained_prefix, "203.0.113.0");
        assert!(matches!(
            app.take_rib_intent(),
            Some(RibIntent::Query { .. })
        ));
        assert_eq!(app.take_rib_intent(), Some(RibIntent::Cancel));
    }
}
