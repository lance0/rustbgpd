use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;

use crate::output::parse_prefix_addr;
use crate::proto::{
    ExplainAdvertisedRouteResponse, GlobalState, HealthResponse, ListRejectedRoutesResponse,
    ListRoutesResponse, NeighborState,
};
use crate::tui::data::{
    DataSnapshot, Freshness, PrefixFilter, RibFamily, RibQueryError, RibQueryIdentity,
    RibQueryKind, RibQueryResponse, RibQueryResult, RibView, RouteEventEntry, RouteEventUpdate,
};

const MAX_EVENTS: usize = 100;

/// Status-line text for the single page-1 restart after a stale token.
pub const RIB_RESTART_NOTICE: &str = "table changed — refreshed at page 1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum View {
    PeerTable,
    PeerDetail(String),
    /// On-demand route explorer; the peer is the scope for Received,
    /// Advertised, and Rejected and the export-explain target for Best.
    RouteExplorer(String),
    AdvertisedExplain(String),
}

#[derive(Debug)]
pub enum RibPageState {
    Loading,
    Ready(ListRoutesResponse),
    /// Rejected routes after client-side family/prefix filtering;
    /// `retained` is the unfiltered count the daemon returned.
    Rejected {
        page: ListRejectedRoutesResponse,
        retained: usize,
    },
    Error(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditorMode {
    /// Submit applies an exact prefix filter (empty input clears it).
    Filter,
    /// Submit explains the typed prefix for the selected peer.
    Explain,
}

/// Single-line exact-prefix editor. ASCII only so the cursor is a byte offset.
#[derive(Debug)]
pub struct PrefixEditor {
    pub mode: EditorMode,
    pub input: String,
    pub cursor: usize,
    pub longer: bool,
    pub error: Option<String>,
}

impl PrefixEditor {
    fn new(mode: EditorMode, input: String, longer: bool) -> Self {
        Self {
            mode,
            cursor: input.len(),
            input,
            longer,
            error: None,
        }
    }

    fn insert(&mut self, c: char) {
        if c.is_ascii() && !c.is_ascii_control() {
            self.input.insert(self.cursor, c);
            self.cursor += 1;
        }
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.input.remove(self.cursor);
        }
    }

    fn delete(&mut self) {
        if self.cursor < self.input.len() {
            self.input.remove(self.cursor);
        }
    }

    /// Parse the input as an exact prefix in `family`; `Ok(None)` is an
    /// empty filter-mode input, which clears the active filter.
    fn parse(&self, family: RibFamily) -> Result<Option<(IpAddr, u32)>, String> {
        let text = self.input.trim();
        if text.is_empty() {
            return match self.mode {
                EditorMode::Filter => Ok(None),
                EditorMode::Explain => Err("enter a prefix".to_string()),
            };
        }
        let (addr, len) = parse_prefix_addr(text)?;
        if !family.matches(addr) {
            let typed = if addr.is_ipv4() { "IPv4" } else { "IPv6" };
            return Err(format!(
                "{typed} prefix does not match {} (f toggles family)",
                family.label()
            ));
        }
        Ok(Some((addr, len)))
    }
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
    pub rib_view: RibView,
    pub rib_family: RibFamily,
    pub rib_filter: Option<PrefixFilter>,
    /// Visible data rows reported by the last draw; drives Space/PgDn/PgUp.
    pub rib_page_height: usize,
    pub rib_notice: Option<&'static str>,
    pub rib_editor: Option<PrefixEditor>,
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
            rib_view: RibView::Best,
            rib_family: RibFamily::Ipv4Unicast,
            rib_filter: None,
            rib_page_height: 0,
            rib_notice: None,
            rib_editor: None,
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
            View::RouteExplorer(_) => self.handle_rib_key(key),
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
                    self.open_explorer(peer);
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

    fn list_query(&self, page_token: String) -> RibQueryKind {
        RibQueryKind::List {
            view: self.rib_view,
            family: self.rib_family,
            filter: self.rib_filter,
            page_token,
        }
    }

    /// Start the explorer over at page 1 of the current view/family/filter.
    ///
    /// Every selector change routes through here so the token stack, the
    /// single ABORTED restart, the selection, and the screen offset can never
    /// outlive the scope they were built for. Callers cancel first.
    fn reset_explorer_page(&mut self, peer: String) {
        self.next_view_id();
        self.rib_page_token.clear();
        self.rib_previous_tokens.clear();
        self.rib_table_state = TableState::default();
        self.rib_notice = None;
        self.rib_editor = None;
        self.aborted_reset_used = false;
        self.rib_page = Some(RibPageState::Loading);
        self.queue_query(peer, self.list_query(String::new()));
    }

    fn open_explorer(&mut self, peer: String) {
        self.cancel_rib();
        self.view = View::RouteExplorer(peer.clone());
        self.reset_explorer_page(peer);
    }

    fn restart_explorer(&mut self, peer: String) {
        self.cancel_rib();
        self.reset_explorer_page(peer);
    }

    fn request_page(&mut self, peer: String, token: String) {
        self.rib_page = Some(RibPageState::Loading);
        self.queue_query(peer, self.list_query(token));
    }

    fn open_explain(&mut self, peer: String, prefix: String, prefix_length: u32) {
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

    fn selected_route_prefix(&self) -> Option<(String, u32)> {
        let selected = self.rib_table_state.selected()?;
        match &self.rib_page {
            Some(RibPageState::Ready(page)) => page
                .routes
                .get(selected)
                .map(|route| (route.prefix.clone(), route.prefix_length)),
            _ => None,
        }
    }

    fn handle_rib_key(&mut self, key: KeyEvent) {
        let peer = match &self.view {
            View::RouteExplorer(peer) => peer.clone(),
            _ => return,
        };
        if self.rib_editor.is_some() {
            self.handle_editor_key(key, peer);
            return;
        }
        match key.code {
            KeyCode::Char('q') => {
                self.cancel_rib();
                self.should_quit = true;
            }
            KeyCode::Char('h') => self.show_help = true,
            KeyCode::Esc | KeyCode::Backspace => {
                self.cancel_rib();
                self.view = View::PeerDetail(peer);
            }
            KeyCode::Char('j') | KeyCode::Down => self.select_next_route(),
            KeyCode::Char('k') | KeyCode::Up => self.select_prev_route(),
            KeyCode::Char(' ') | KeyCode::PageDown => {
                self.move_route_selection(self.rib_page_height.max(1) as isize)
            }
            KeyCode::PageUp => self.move_route_selection(-(self.rib_page_height.max(1) as isize)),
            KeyCode::Home => self.move_route_selection(isize::MIN),
            KeyCode::End => self.move_route_selection(isize::MAX),
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
            KeyCode::Char('v') => {
                self.rib_view = self.rib_view.next();
                self.restart_explorer(peer);
            }
            KeyCode::Char('f') => {
                self.rib_family = self.rib_family.toggle();
                // A filter from the other family can never match; drop it
                // rather than sending a request the daemon rejects.
                if self
                    .rib_filter
                    .is_some_and(|filter| !self.rib_family.matches(filter.addr))
                {
                    self.rib_filter = None;
                }
                self.restart_explorer(peer);
            }
            KeyCode::Char('r') => self.restart_explorer(peer),
            KeyCode::Char('/') => {
                let (input, longer) = self.rib_filter.map_or((String::new(), false), |filter| {
                    (format!("{}/{}", filter.addr, filter.len), filter.longer)
                });
                self.rib_editor = Some(PrefixEditor::new(EditorMode::Filter, input, longer));
            }
            KeyCode::Char('e') => {
                let input = self
                    .selected_route_prefix()
                    .map_or(String::new(), |(prefix, len)| format!("{prefix}/{len}"));
                self.rib_editor = Some(PrefixEditor::new(EditorMode::Explain, input, false));
            }
            KeyCode::Enter => {
                if self.rib_view.explains_rows()
                    && let Some((prefix, prefix_length)) = self.selected_route_prefix()
                {
                    self.open_explain(peer, prefix, prefix_length);
                }
            }
            _ => {}
        }
    }

    fn handle_editor_key(&mut self, key: KeyEvent, peer: String) {
        let Some(editor) = self.rib_editor.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.rib_editor = None,
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                editor.insert(c);
                editor.error = None;
            }
            KeyCode::Backspace => editor.backspace(),
            KeyCode::Delete => editor.delete(),
            KeyCode::Left => editor.cursor = editor.cursor.saturating_sub(1),
            KeyCode::Right => editor.cursor = (editor.cursor + 1).min(editor.input.len()),
            KeyCode::Home => editor.cursor = 0,
            KeyCode::End => editor.cursor = editor.input.len(),
            KeyCode::Tab if editor.mode == EditorMode::Filter => editor.longer = !editor.longer,
            KeyCode::Enter => match editor.parse(self.rib_family) {
                Err(error) => editor.error = Some(error),
                Ok(parsed) => {
                    let mode = editor.mode;
                    let longer = editor.longer;
                    self.rib_editor = None;
                    match (mode, parsed) {
                        (EditorMode::Filter, parsed) => {
                            let filter =
                                parsed.map(|(addr, len)| PrefixFilter { addr, len, longer });
                            if filter != self.rib_filter {
                                self.rib_filter = filter;
                                self.restart_explorer(peer);
                            }
                        }
                        (EditorMode::Explain, Some((addr, len))) => {
                            self.open_explain(peer, addr.to_string(), len);
                        }
                        (EditorMode::Explain, None) => {}
                    }
                }
            },
            _ => {}
        }
    }

    /// Move the highlight within the current page; never issues a query.
    fn move_route_selection(&mut self, delta: isize) {
        let n = self.route_count();
        if n == 0 {
            return;
        }
        let current = self.rib_table_state.selected().unwrap_or(0) as isize;
        let target = current.saturating_add(delta).clamp(0, n as isize - 1);
        self.rib_table_state.select(Some(target as usize));
    }

    pub(crate) fn set_rib_layout(&mut self, visible_rows: usize) {
        self.rib_page_height = visible_rows;
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
                self.view = View::RouteExplorer(peer);
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
            Some(RibPageState::Rejected { page, .. }) => page.routes.len(),
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
            || matches!(
                self.view,
                View::RouteExplorer(_) | View::AdvertisedExplain(_)
            )
        {
            // A late result for the cancelled request must fail the
            // identity check even if the lane had already sent it.
            self.next_view_id();
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
            (
                View::RouteExplorer(peer),
                RibQueryKind::List {
                    view,
                    family,
                    filter,
                    ..
                },
            ) => {
                peer == &active.peer_address
                    && *view == self.rib_view
                    && *family == self.rib_family
                    && *filter == self.rib_filter
            }
            (View::AdvertisedExplain(peer), RibQueryKind::ExplainAdvertised { .. }) => {
                peer == &active.peer_address
            }
            _ => false,
        };
        if !expected_view {
            self.active_rib_query = Some(active);
            return;
        }
        match result.result {
            Ok(RibQueryResponse::Page(page)) => {
                let RibQueryKind::List { page_token, .. } = active.query else {
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
            Ok(RibQueryResponse::Rejected(mut page)) => {
                let RibQueryKind::List { family, filter, .. } = active.query else {
                    return;
                };
                let retained = page.routes.len();
                page.routes.retain(|route| {
                    route.afi_safi == family.afi_safi()
                        && filter.is_none_or(|filter| {
                            route
                                .prefix
                                .parse::<IpAddr>()
                                .is_ok_and(|addr| filter.matches(addr, route.prefix_length))
                        })
                });
                self.rib_table_state
                    .select((!page.routes.is_empty()).then_some(0));
                self.rib_page = Some(RibPageState::Rejected { page, retained });
            }
            Ok(RibQueryResponse::ExplainAdvertised(explain)) => {
                self.explain = Some(ExplainState::Ready(explain))
            }
            Err(error)
                if error.code == tonic::Code::Aborted
                    && matches!(active.query, RibQueryKind::List { ref page_token, .. } if !page_token.is_empty())
                    && !self.aborted_reset_used =>
            {
                self.aborted_reset_used = true;
                self.rib_previous_tokens.clear();
                self.rib_page_token.clear();
                self.rib_notice = Some(RIB_RESTART_NOTICE);
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
        self.rib_editor = None;
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
            View::PeerDetail(peer) | View::RouteExplorer(peer) | View::AdvertisedExplain(peer) => {
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
        assert_eq!(query, best(""));
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
            result: Ok(RibQueryResponse::Page(page("203.0.113.0", "next\0opaque"))),
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
        assert_eq!(query, best("next\0opaque"));
        let next = RibQueryIdentity {
            request_id: 8,
            view_id,
            peer_address,
            query,
        };
        app.record_rib_request(next.clone());
        app.on_rib_result(RibQueryResult {
            identity: next,
            result: Ok(RibQueryResponse::Page(page("203.0.114.0", ""))),
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
                3 => stale.query = best("x"),
                _ => app.view = View::PeerDetail(active.peer_address.clone()),
            }
            app.on_rib_result(RibQueryResult {
                identity: stale,
                result: Ok(RibQueryResponse::Page(page("203.0.113.0", ""))),
            });
            assert!(matches!(app.rib_page, Some(RibPageState::Loading)));
            assert_eq!(app.active_rib_query, Some(active.clone()));
            app.view = View::RouteExplorer(active.peer_address.clone());
        }
    }

    #[test]
    fn aborted_page_resets_once_and_errors_are_exact() {
        let mut app = App::new();
        let first = open_rib(&mut app);
        app.on_rib_result(RibQueryResult {
            identity: first,
            result: Ok(RibQueryResponse::Page(page("203.0.113.0", "opaque"))),
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
        assert_eq!(query, best(""));
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
        assert!(matches!(app.view, View::RouteExplorer(_)));
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
            result: Ok(RibQueryResponse::Page(page("203.0.113.0", ""))),
        });
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let retained_prefix = match &app.rib_page {
            Some(RibPageState::Ready(page)) => page.routes[0].prefix.clone(),
            _ => panic!(),
        };
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.view, View::RouteExplorer("198.51.100.1".into()));
        assert_eq!(retained_prefix, "203.0.113.0");
        assert!(matches!(
            app.take_rib_intent(),
            Some(RibIntent::Query { .. })
        ));
        assert_eq!(app.take_rib_intent(), Some(RibIntent::Cancel));
    }

    fn best(token: &str) -> RibQueryKind {
        RibQueryKind::List {
            view: RibView::Best,
            family: RibFamily::Ipv4Unicast,
            filter: None,
            page_token: token.into(),
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
    }

    fn record(
        app: &mut App,
        request_id: u64,
        view_id: u64,
        peer_address: String,
        query: RibQueryKind,
    ) -> RibQueryIdentity {
        let identity = RibQueryIdentity {
            request_id,
            view_id,
            peer_address,
            query,
        };
        app.record_rib_request(identity.clone());
        identity
    }

    /// Every explorer transition emits exactly `Cancel` then one `Query`
    /// minted for the current view id.
    fn take_cancel_then_query(app: &mut App) -> (u64, String, RibQueryKind) {
        assert_eq!(app.take_rib_intent(), Some(RibIntent::Cancel));
        let Some(RibIntent::Query {
            view_id,
            peer_address,
            query,
        }) = app.take_rib_intent()
        else {
            panic!("expected a query after cancel")
        };
        assert!(app.take_rib_intent().is_none());
        assert_eq!(view_id, app.view_id);
        (view_id, peer_address, query)
    }

    fn assert_explorer_reset(app: &App) {
        assert!(app.rib_page_token.is_empty());
        assert!(app.rib_previous_tokens.is_empty());
        assert!(!app.aborted_reset_used);
        assert_eq!(app.rib_table_state.selected(), None);
        assert_eq!(app.rib_table_state.offset(), 0);
        assert!(app.rib_notice.is_none());
        assert!(app.rib_editor.is_none());
        assert!(matches!(app.rib_page, Some(RibPageState::Loading)));
    }

    fn filter(prefix: &str, len: u32, longer: bool) -> PrefixFilter {
        PrefixFilter {
            addr: prefix.parse().unwrap(),
            len,
            longer,
        }
    }

    #[test]
    fn explorer_view_cycle_scopes_queries_and_resets_every_transition() {
        let mut app = App::new();
        let first = open_rib(&mut app);
        app.on_rib_result(RibQueryResult {
            identity: first,
            result: Ok(RibQueryResponse::Page(page("203.0.113.0", "tok"))),
        });
        app.on_key(key(KeyCode::Char('n')));
        let Some(RibIntent::Query {
            view_id,
            peer_address,
            query,
        }) = app.take_rib_intent()
        else {
            panic!()
        };
        let paged = record(&mut app, 8, view_id, peer_address, query);
        app.on_rib_result(RibQueryResult {
            identity: paged,
            result: Ok(RibQueryResponse::Page(page("203.0.114.0", ""))),
        });
        app.rib_table_state.select(Some(0));
        *app.rib_table_state.offset_mut() = 3;
        app.aborted_reset_used = true;
        app.rib_notice = Some(RIB_RESTART_NOTICE);
        assert_eq!(app.rib_previous_tokens.len(), 1);

        let mut previous_view_id = view_id;
        for expected in [
            RibView::Received,
            RibView::Advertised,
            RibView::Rejected,
            RibView::Best,
        ] {
            app.on_key(key(KeyCode::Char('v')));
            assert_eq!(app.rib_view, expected);
            assert_explorer_reset(&app);
            let (view_id, peer_address, query) = take_cancel_then_query(&mut app);
            assert!(view_id > previous_view_id);
            previous_view_id = view_id;
            assert_eq!(peer_address, "198.51.100.1");
            assert_eq!(
                query,
                RibQueryKind::List {
                    view: expected,
                    family: RibFamily::Ipv4Unicast,
                    filter: None,
                    page_token: String::new()
                }
            );
            record(&mut app, view_id, view_id, peer_address, query);
        }
        assert!(
            !app.rib_view.peer_scoped(),
            "Rejected -> Best returns to global scope"
        );
        assert_eq!(app.view, View::RouteExplorer("198.51.100.1".into()));
    }

    #[test]
    fn explorer_stale_results_are_dropped_after_every_transition() {
        type Transition = fn(&mut App);
        let transitions: Vec<(&str, Transition)> = vec![
            ("view", |app| app.on_key(key(KeyCode::Char('v')))),
            ("family", |app| app.on_key(key(KeyCode::Char('f')))),
            ("filter", |app| {
                app.on_key(key(KeyCode::Char('/')));
                type_text(app, "203.0.113.0/24");
                app.on_key(key(KeyCode::Enter));
            }),
            ("refresh", |app| app.on_key(key(KeyCode::Char('r')))),
            ("leave", |app| app.on_key(key(KeyCode::Esc))),
            ("peer loss", |app| app.on_data(snapshot(Vec::new()))),
            ("peer swap", |app| {
                app.on_data(snapshot(vec![neighbor("198.51.100.2", 10)]))
            }),
        ];
        for (name, transition) in transitions {
            let mut app = App::new();
            let stale = open_rib(&mut app);
            transition(&mut app);
            assert_ne!(app.view_id, stale.view_id, "{name} must mint a new view id");
            assert_eq!(
                app.take_rib_intent(),
                Some(RibIntent::Cancel),
                "{name} must cancel"
            );
            if matches!(app.view, View::RouteExplorer(_)) {
                let Some(RibIntent::Query {
                    view_id,
                    peer_address,
                    query,
                }) = app.take_rib_intent()
                else {
                    panic!("{name} must re-query")
                };
                assert_eq!(view_id, app.view_id);
                record(&mut app, 9, view_id, peer_address, query);
            } else {
                assert!(
                    matches!(app.view, View::PeerDetail(_) | View::PeerTable),
                    "{name}: {:?}",
                    app.view
                );
                assert!(app.take_rib_intent().is_none(), "{name}");
                assert!(app.active_rib_query.is_none(), "{name}");
            }
            app.on_rib_result(RibQueryResult {
                identity: stale.clone(),
                result: Ok(RibQueryResponse::Page(page("203.0.113.0", ""))),
            });
            assert!(
                matches!(app.rib_page, Some(RibPageState::Loading)),
                "{name}: stale page must not render"
            );
            if let Some(active) = &app.active_rib_query {
                assert_eq!(active.view_id, app.view_id, "{name}: live request kept");
            }
        }
    }

    #[test]
    fn explorer_family_toggle_reaches_request_and_drops_mismatched_filter() {
        let mut app = App::new();
        open_rib(&mut app);
        app.rib_filter = Some(filter("203.0.113.0", 24, false));

        app.on_key(key(KeyCode::Char('f')));
        assert_eq!(app.rib_family, RibFamily::Ipv6Unicast);
        assert_eq!(app.rib_filter, None, "an IPv4 filter cannot survive IPv6");
        assert_explorer_reset(&app);
        let (_, _, query) = take_cancel_then_query(&mut app);
        assert_eq!(
            query,
            RibQueryKind::List {
                view: RibView::Best,
                family: RibFamily::Ipv6Unicast,
                filter: None,
                page_token: String::new()
            }
        );

        app.rib_filter = Some(filter("2001:db8::", 32, true));
        app.rib_view = RibView::Received;
        app.on_key(key(KeyCode::Char('f')));
        assert_eq!(app.rib_family, RibFamily::Ipv4Unicast);
        assert_eq!(app.rib_filter, None);
        take_cancel_then_query(&mut app);
    }

    #[test]
    fn explorer_filter_editor_validates_without_querying_and_applies_longer() {
        let mut app = App::new();
        open_rib(&mut app);

        app.on_key(key(KeyCode::Char('/')));
        assert_eq!(
            app.rib_editor.as_ref().map(|editor| editor.mode),
            Some(EditorMode::Filter)
        );
        type_text(&mut app, "not-a-prefix");
        app.on_key(key(KeyCode::Enter));
        let error = app.rib_editor.as_ref().unwrap().error.clone().unwrap();
        assert!(error.contains("invalid IP address"), "{error}");
        assert!(app.take_rib_intent().is_none());
        assert_eq!(app.rib_filter, None);

        // Command keys are text while the editor is open; typing clears the
        // error; Esc cancels without touching the active filter.
        app.on_key(key(KeyCode::Char('q')));
        assert!(!app.should_quit);
        assert_eq!(app.rib_editor.as_ref().unwrap().input, "not-a-prefixq");
        assert!(app.rib_editor.as_ref().unwrap().error.is_none());
        app.on_key(key(KeyCode::Esc));
        assert!(app.rib_editor.is_none());
        assert_eq!(app.rib_filter, None);
        assert!(app.take_rib_intent().is_none());

        for (input, expected) in [
            (
                "2001:db8::/32",
                "IPv6 prefix does not match IPv4 unicast (f toggles family)",
            ),
            ("203.0.113.0/33", "prefix length 33 exceeds 32 for IPv4"),
        ] {
            app.on_key(key(KeyCode::Char('/')));
            type_text(&mut app, input);
            app.on_key(key(KeyCode::Enter));
            assert_eq!(
                app.rib_editor.as_ref().unwrap().error.as_deref(),
                Some(expected)
            );
            assert!(app.take_rib_intent().is_none());
            assert_eq!(app.rib_filter, None);
            app.on_key(key(KeyCode::Esc));
        }

        app.on_key(key(KeyCode::Char('/')));
        type_text(&mut app, "03.0.113.0/25");
        app.on_key(key(KeyCode::Backspace));
        type_text(&mut app, "4");
        app.on_key(key(KeyCode::Home));
        type_text(&mut app, "2");
        app.on_key(key(KeyCode::Right));
        app.on_key(key(KeyCode::Delete));
        app.on_key(key(KeyCode::End));
        app.on_key(key(KeyCode::Left));
        app.on_key(key(KeyCode::Char('\u{00e9}')));
        assert_eq!(app.rib_editor.as_ref().unwrap().input, "20.0.113.0/24");
        app.on_key(key(KeyCode::Home));
        app.on_key(key(KeyCode::Right));
        app.on_key(key(KeyCode::Right));
        type_text(&mut app, "3");
        assert_eq!(app.rib_editor.as_ref().unwrap().input, "203.0.113.0/24");
        app.on_key(key(KeyCode::Tab));
        assert!(app.rib_editor.as_ref().unwrap().longer);
        app.on_key(key(KeyCode::Enter));
        assert!(app.rib_editor.is_none());
        assert_eq!(app.rib_filter, Some(filter("203.0.113.0", 24, true)));
        assert_explorer_reset(&app);
        let (_, _, query) = take_cancel_then_query(&mut app);
        assert_eq!(
            query,
            RibQueryKind::List {
                view: RibView::Best,
                family: RibFamily::Ipv4Unicast,
                filter: Some(filter("203.0.113.0", 24, true)),
                page_token: String::new()
            }
        );

        // Reopening prefills the active filter; an unchanged submit is silent.
        app.on_key(key(KeyCode::Char('/')));
        let editor = app.rib_editor.as_ref().unwrap();
        assert_eq!(editor.input, "203.0.113.0/24");
        assert!(editor.longer);
        app.on_key(key(KeyCode::Enter));
        assert!(app.rib_editor.is_none());
        assert!(app.take_rib_intent().is_none());

        // An empty submit clears the filter and re-queries.
        app.on_key(key(KeyCode::Char('/')));
        for _ in 0..14 {
            app.on_key(key(KeyCode::Backspace));
        }
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.rib_filter, None);
        let (_, _, query) = take_cancel_then_query(&mut app);
        assert_eq!(query, best(""));
    }

    #[test]
    fn explorer_screen_paging_moves_selection_without_query_and_server_paging_queries() {
        let mut app = App::new();
        let first = open_rib(&mut app);
        let mut big = page("203.0.113.0", "next");
        big.routes = (0..10)
            .map(|i| crate::proto::Route {
                prefix: format!("203.0.{i}.0"),
                prefix_length: 24,
                ..Default::default()
            })
            .collect();
        app.on_rib_result(RibQueryResult {
            identity: first,
            result: Ok(RibQueryResponse::Page(big)),
        });
        app.set_rib_layout(4);

        app.on_key(key(KeyCode::Char(' ')));
        assert_eq!(app.rib_table_state.selected(), Some(4));
        app.on_key(key(KeyCode::PageDown));
        assert_eq!(app.rib_table_state.selected(), Some(8));
        app.on_key(key(KeyCode::PageDown));
        assert_eq!(
            app.rib_table_state.selected(),
            Some(9),
            "screen moves clamp inside the server page"
        );
        app.on_key(key(KeyCode::PageUp));
        assert_eq!(app.rib_table_state.selected(), Some(5));
        app.on_key(key(KeyCode::Home));
        assert_eq!(app.rib_table_state.selected(), Some(0));
        app.on_key(key(KeyCode::End));
        assert_eq!(app.rib_table_state.selected(), Some(9));
        assert!(app.take_rib_intent().is_none(), "screen moves never query");
        assert!(app.rib_previous_tokens.is_empty());
        assert!(matches!(app.rib_page, Some(RibPageState::Ready(_))));

        app.on_key(key(KeyCode::Char('n')));
        let Some(RibIntent::Query { query, .. }) = app.take_rib_intent() else {
            panic!("n issues a server page query")
        };
        assert_eq!(query, best("next"));
        assert!(matches!(app.rib_page, Some(RibPageState::Loading)));
    }

    #[test]
    fn explorer_rejected_rows_are_filtered_client_side_and_enter_is_inert() {
        let mut app = App::new();
        open_rib(&mut app);
        app.rib_filter = Some(filter("203.0.113.0", 24, true));
        app.rib_view = RibView::Advertised;
        app.on_key(key(KeyCode::Char('v')));
        assert_eq!(app.rib_view, RibView::Rejected);
        let (view_id, peer_address, query) = take_cancel_then_query(&mut app);
        assert_eq!(
            query,
            RibQueryKind::List {
                view: RibView::Rejected,
                family: RibFamily::Ipv4Unicast,
                filter: Some(filter("203.0.113.0", 24, true)),
                page_token: String::new()
            }
        );
        let identity = record(&mut app, 11, view_id, peer_address, query);
        let rejected = |prefix: &str, len: u32, afi_safi: i32| crate::proto::RejectedRoute {
            prefix: prefix.into(),
            prefix_length: len,
            afi_safi,
            reason: "policy_reject".into(),
            ..Default::default()
        };
        app.on_rib_result(RibQueryResult {
            identity,
            result: Ok(RibQueryResponse::Rejected(ListRejectedRoutesResponse {
                peer_address: "198.51.100.1".into(),
                retention_enabled: true,
                capacity: 8,
                routes: vec![
                    rejected("203.0.113.0", 24, 1),
                    rejected("203.0.113.128", 25, 1),
                    rejected("203.0.114.0", 24, 1),
                    rejected("2001:db8::", 32, 2),
                    rejected("203.0.113.0", 23, 1),
                    rejected("not-an-address", 24, 1),
                ],
                evictions_since_reset: Some(0),
            })),
        });
        let Some(RibPageState::Rejected { page, retained }) = &app.rib_page else {
            panic!("rejected listing")
        };
        assert_eq!(*retained, 6);
        let kept: Vec<String> = page
            .routes
            .iter()
            .map(|route| format!("{}/{}", route.prefix, route.prefix_length))
            .collect();
        assert_eq!(kept, vec!["203.0.113.0/24", "203.0.113.128/25"]);
        assert_eq!(app.rib_table_state.selected(), Some(0));

        app.on_key(key(KeyCode::Enter));
        assert!(app.take_rib_intent().is_none());
        assert_eq!(app.view, View::RouteExplorer("198.51.100.1".into()));
        app.on_key(key(KeyCode::Char('n')));
        assert!(app.take_rib_intent().is_none(), "rejected has one page");

        // Family alone filters when no prefix is set.
        app.rib_filter = None;
        app.on_key(key(KeyCode::Char('f')));
        let (view_id, peer_address, query) = take_cancel_then_query(&mut app);
        let identity = record(&mut app, 12, view_id, peer_address, query);
        app.on_rib_result(RibQueryResult {
            identity,
            result: Ok(RibQueryResponse::Rejected(ListRejectedRoutesResponse {
                peer_address: "198.51.100.1".into(),
                retention_enabled: true,
                capacity: 8,
                routes: vec![
                    rejected("203.0.113.0", 24, 1),
                    rejected("2001:db8::", 32, 2),
                ],
                evictions_since_reset: None,
            })),
        });
        let Some(RibPageState::Rejected { page, retained }) = &app.rib_page else {
            panic!("rejected listing")
        };
        assert_eq!((*retained, page.routes.len()), (2, 1));
        assert_eq!(page.routes[0].prefix, "2001:db8::");
    }

    #[test]
    fn explorer_empty_pages_for_every_view_select_nothing() {
        let mut app = App::new();
        let mut identity = open_rib(&mut app);
        for view in [
            RibView::Best,
            RibView::Received,
            RibView::Advertised,
            RibView::Rejected,
        ] {
            if view != RibView::Best {
                app.on_key(key(KeyCode::Char('v')));
                let (view_id, peer_address, query) = take_cancel_then_query(&mut app);
                identity = record(&mut app, view_id, view_id, peer_address, query);
            }
            assert_eq!(app.rib_view, view);
            let result = if view == RibView::Rejected {
                RibQueryResponse::Rejected(ListRejectedRoutesResponse::default())
            } else {
                RibQueryResponse::Page(ListRoutesResponse::default())
            };
            app.on_rib_result(RibQueryResult {
                identity: identity.clone(),
                result: Ok(result),
            });
            assert_eq!(app.rib_table_state.selected(), None, "{view:?}");
            assert!(app.active_rib_query.is_none(), "{view:?}");
            app.on_key(key(KeyCode::Enter));
            app.on_key(key(KeyCode::Char(' ')));
            app.on_key(key(KeyCode::Char('n')));
            assert!(app.take_rib_intent().is_none(), "{view:?}");
            assert_eq!(app.view, View::RouteExplorer("198.51.100.1".into()));
        }
    }

    #[test]
    fn explorer_aborted_restart_is_named_once_then_second_abort_errors() {
        let mut app = App::new();
        let first = open_rib(&mut app);
        app.on_rib_result(RibQueryResult {
            identity: first,
            result: Ok(RibQueryResponse::Page(page("203.0.113.0", "opaque"))),
        });
        let aborted = || {
            Err(RibQueryError {
                code: tonic::Code::Aborted,
                message: "changed".into(),
            })
        };

        app.on_key(key(KeyCode::Char('n')));
        let Some(RibIntent::Query {
            view_id,
            peer_address,
            query,
        }) = app.take_rib_intent()
        else {
            panic!()
        };
        let paged = record(&mut app, 8, view_id, peer_address, query);
        app.on_rib_result(RibQueryResult {
            identity: paged,
            result: aborted(),
        });
        assert_eq!(app.rib_notice, Some(RIB_RESTART_NOTICE));
        assert!(app.aborted_reset_used);
        assert!(app.rib_previous_tokens.is_empty());
        assert!(app.rib_page_token.is_empty());
        assert!(matches!(app.rib_page, Some(RibPageState::Loading)));
        let Some(RibIntent::Query {
            view_id,
            peer_address,
            query,
        }) = app.take_rib_intent()
        else {
            panic!()
        };
        assert_eq!(query, best(""));
        let restart = record(&mut app, 9, view_id, peer_address, query);
        app.on_rib_result(RibQueryResult {
            identity: restart,
            result: Ok(RibQueryResponse::Page(page("203.0.113.0", "opaque2"))),
        });
        assert_eq!(
            app.rib_notice,
            Some(RIB_RESTART_NOTICE),
            "the notice stays until the next transition"
        );

        app.on_key(key(KeyCode::Char('n')));
        let Some(RibIntent::Query {
            view_id,
            peer_address,
            query,
        }) = app.take_rib_intent()
        else {
            panic!()
        };
        let paged = record(&mut app, 10, view_id, peer_address, query);
        app.on_rib_result(RibQueryResult {
            identity: paged,
            result: aborted(),
        });
        assert!(matches!(
            &app.rib_page,
            Some(RibPageState::Error(text)) if text == "RIB snapshot expired: changed"
        ));
        assert!(app.take_rib_intent().is_none());

        app.on_key(key(KeyCode::Char('r')));
        assert_explorer_reset(&app);
        take_cancel_then_query(&mut app);
    }

    #[test]
    fn explorer_explain_uses_typed_prefix_and_enter_only_on_export_candidates() {
        let mut app = App::new();
        let first = open_rib(&mut app);
        app.on_rib_result(RibQueryResult {
            identity: first,
            result: Ok(RibQueryResponse::Page(page("203.0.113.0", ""))),
        });

        app.on_key(key(KeyCode::Char('e')));
        let editor = app.rib_editor.as_ref().unwrap();
        assert_eq!(editor.mode, EditorMode::Explain);
        assert_eq!(
            editor.input, "203.0.113.0/24",
            "prefills the highlighted row"
        );
        for _ in 0..14 {
            app.on_key(key(KeyCode::Backspace));
        }
        app.on_key(key(KeyCode::Enter));
        assert_eq!(
            app.rib_editor.as_ref().unwrap().error.as_deref(),
            Some("enter a prefix")
        );
        assert!(app.take_rib_intent().is_none());
        app.on_key(key(KeyCode::Tab));
        assert!(
            !app.rib_editor.as_ref().unwrap().longer,
            "no longer toggle in explain mode"
        );

        type_text(&mut app, "198.51.100.0/22");
        app.on_key(key(KeyCode::Enter));
        assert!(app.rib_editor.is_none());
        assert_eq!(app.view, View::AdvertisedExplain("198.51.100.1".into()));
        assert!(matches!(app.explain, Some(ExplainState::Loading)));
        let Some(RibIntent::Query {
            view_id,
            peer_address,
            query,
        }) = app.take_rib_intent()
        else {
            panic!()
        };
        assert_eq!(view_id, app.view_id);
        assert_eq!(peer_address, "198.51.100.1");
        assert_eq!(
            query,
            RibQueryKind::ExplainAdvertised {
                prefix: "198.51.100.0".into(),
                prefix_length: 22
            }
        );

        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.take_rib_intent(), Some(RibIntent::Cancel));
        assert_eq!(app.view, View::RouteExplorer("198.51.100.1".into()));
        assert!(matches!(app.rib_page, Some(RibPageState::Ready(_))));

        app.rib_view = RibView::Received;
        app.on_key(key(KeyCode::Enter));
        assert!(app.take_rib_intent().is_none());
        assert_eq!(app.view, View::RouteExplorer("198.51.100.1".into()));
        app.rib_view = RibView::Advertised;
        app.on_key(key(KeyCode::Enter));
        assert!(matches!(
            app.take_rib_intent(),
            Some(RibIntent::Query {
                query: RibQueryKind::ExplainAdvertised { .. },
                ..
            })
        ));
        assert_eq!(app.view, View::AdvertisedExplain("198.51.100.1".into()));
    }
}
