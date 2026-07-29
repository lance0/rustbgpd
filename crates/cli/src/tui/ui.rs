use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};

use crate::output::{format_duration, format_family, format_state_with_stale};
use crate::tui::app::{App, SortColumn, View, neighbor_key};
use crate::tui::data::Freshness;
use crate::tui::theme::Theme;

pub fn draw(f: &mut Frame, app: &mut App, theme: &Theme) {
    match app.view.clone() {
        View::PeerTable => draw_main(f, app, theme),
        View::PeerDetail(address) => draw_peer_detail(f, app, &address, theme),
    }

    if app.show_help {
        draw_help_overlay(f, theme);
    }
}

fn draw_main(f: &mut Frame, app: &mut App, theme: &Theme) {
    let chunks = if app.show_events {
        Layout::vertical([
            Constraint::Length(3), // header
            Constraint::Min(5),    // peer table
            Constraint::Length(8), // events
            Constraint::Length(1), // footer
        ])
        .split(f.area())
    } else {
        Layout::vertical([
            Constraint::Length(3), // header
            Constraint::Min(5),    // peer table
            Constraint::Length(1), // footer
        ])
        .split(f.area())
    };

    draw_header(f, app, chunks[0], theme);
    draw_peer_table(f, app, chunks[1], theme);

    if app.show_events {
        draw_events(f, app, chunks[2], theme);
        draw_footer(f, app, chunks[3], theme);
    } else {
        draw_footer(f, app, chunks[2], theme);
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    let asn = app
        .global
        .as_ref()
        .map(|g| format!("AS {}", g.asn))
        .unwrap_or_else(|| "AS ?".into());
    let rid = app
        .global
        .as_ref()
        .map(|g| format!("rid {}", g.router_id))
        .unwrap_or_else(|| "rid ?".into());
    let uptime = app
        .health
        .as_ref()
        .map(|h| format!("up {}", format_duration(h.uptime_seconds)))
        .unwrap_or_else(|| "up ?".into());
    let peers = format!("peers {}/{}", app.established_count(), app.neighbors.len());
    let routes = format!("routes {}", format_number(app.total_routes() as u64));
    let vrp = app
        .rpki_vrp_count
        .map(|c| format!("VRPs {}", format_number(c)))
        .unwrap_or_default();

    let mut parts = vec![asn, rid, uptime, peers, routes];
    if !vrp.is_empty() {
        parts.push(vrp);
    }
    let title = format!(" rustbgpd  {} ", parts.join(" | "));

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));

    let status = if app.connected {
        Span::styled("connected", Style::default().fg(theme.state_established))
    } else {
        let msg = app.last_error.as_deref().unwrap_or("disconnected");
        Span::styled(msg, Style::default().fg(theme.error))
    };

    let mut status_line = vec![Span::raw(" Status: ")];
    let mut stale = Vec::new();
    if !app.health_fresh && app.health.is_some() {
        stale.push("health");
    }
    if app.metrics_freshness == Some(Freshness::Stale) && app.rpki_vrp_count.is_some() {
        stale.push("RPKI");
    }
    if app.neighbors_freshness == Some(Freshness::Stale) {
        stale.push("neighbors");
    }
    if app.global_freshness == Some(Freshness::Unavailable) {
        status_line.push(Span::styled(
            "global unavailable | ",
            Style::default().fg(theme.error),
        ));
    }
    if app.metrics_freshness == Some(Freshness::Unavailable) {
        status_line.push(Span::styled(
            "RPKI unavailable | ",
            Style::default().fg(theme.error),
        ));
    }
    if app.neighbors_freshness == Some(Freshness::Unavailable) {
        status_line.push(Span::styled(
            "neighbors unavailable | ",
            Style::default().fg(theme.error),
        ));
    }
    if !stale.is_empty() {
        status_line.push(Span::styled(
            format!("stale: {} | ", stale.join(", ")),
            Style::default().fg(theme.state_connecting),
        ));
    }
    status_line.push(status);

    let content = Paragraph::new(Line::from(status_line)).block(block);
    f.render_widget(content, area);
}

fn draw_peer_table(f: &mut Frame, app: &mut App, area: Rect, theme: &Theme) {
    if app.neighbors.is_empty() {
        let block = Block::default()
            .borders(Borders::LEFT | Borders::RIGHT)
            .border_style(Style::default().fg(theme.border));
        let empty = Paragraph::new(empty_peer_message(app))
            .alignment(Alignment::Center)
            .block(block);
        f.render_widget(empty, area);
        return;
    }

    let sort_col = app.sort_column;
    let sort_asc = app.sort_ascending;

    let header_cells = [
        SortColumn::Address,
        SortColumn::Asn,
        SortColumn::State,
        SortColumn::Uptime,
        SortColumn::RxPfx,
        SortColumn::TxPfx,
        SortColumn::UpdateRate,
        SortColumn::Flaps,
    ]
    .iter()
    .map(|&col| {
        let label = if col == sort_col {
            let arrow = if sort_asc { "^" } else { "v" };
            format!("{} {arrow}", col.label())
        } else {
            col.label().to_string()
        };
        Cell::from(label).style(
            Style::default()
                .fg(theme.header_fg)
                .add_modifier(Modifier::BOLD),
        )
    })
    .chain(std::iter::once(
        Cell::from("Description").style(
            Style::default()
                .fg(theme.header_fg)
                .add_modifier(Modifier::BOLD),
        ),
    ));

    let header = Row::new(header_cells).height(1);

    let rows = app.neighbors.iter().map(|n| {
        let cfg = n.config.as_ref();
        let identity = neighbor_key(n).unwrap_or_default();
        let asn = cfg.map(|c| c.remote_asn.to_string()).unwrap_or_default();
        let state_label = format_state_with_stale(n.state, n.stale);
        let state_color = theme.state_color_with_stale(n.state, n.stale);
        let uptime = format_duration(n.uptime_seconds);
        let rx = format_number(n.prefixes_received);
        let tx = format_number(n.prefixes_sent);
        let rate = app.peer_update_rate(&identity);
        let rate_str = if rate < 0.05 {
            "0.0".to_string()
        } else {
            format!("{rate:.1}")
        };
        let flaps = n.flap_count.to_string();
        let desc = cfg.map(|c| c.description.as_str()).unwrap_or("");

        Row::new(vec![
            Cell::from(identity),
            Cell::from(asn),
            Cell::from(state_label).style(Style::default().fg(state_color)),
            Cell::from(uptime),
            Cell::from(rx),
            Cell::from(tx),
            Cell::from(rate_str),
            Cell::from(flaps),
            Cell::from(desc.to_string()),
        ])
    });

    let widths = [
        Constraint::Min(16),    // Neighbor
        Constraint::Length(7),  // AS
        Constraint::Length(11), // State
        Constraint::Length(10), // Uptime
        Constraint::Length(8),  // Rx Pfx
        Constraint::Length(8),  // Tx Pfx
        Constraint::Length(7),  // Upd/s
        Constraint::Length(5),  // Flaps
        Constraint::Min(10),    // Description
    ];

    let block = Block::default()
        .borders(Borders::LEFT | Borders::RIGHT)
        .border_style(Style::default().fg(theme.border));

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(
            Style::default()
                .fg(theme.highlight)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut app.peer_table_state);
}

fn empty_peer_message(app: &App) -> String {
    match app.neighbors_freshness {
        None => "loading peer inventory".to_string(),
        Some(Freshness::Unavailable) => "peer roster unavailable".to_string(),
        _ => match (app.dynamic_ranges_freshness, app.dynamic_range_count) {
            (Some(Freshness::Fresh), Some(0)) => {
                "0 active peers; no peers or dynamic ranges configured".to_string()
            }
            (Some(Freshness::Fresh), Some(1)) => {
                "0 active peers; 1 dynamic range configured".to_string()
            }
            (Some(Freshness::Fresh), Some(count)) => {
                format!("0 active peers; {count} dynamic ranges configured")
            }
            (Some(Freshness::Stale), Some(count)) => {
                format!("0 active peers; last known dynamic range count: {count} (stale)")
            }
            _ => "0 active peers; dynamic ranges unavailable".to_string(),
        },
    }
}

fn draw_events(f: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    let block = Block::default()
        .title(" Route Events ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let max_lines = inner.height as usize;
    let lines: Vec<Line> = app
        .route_events
        .iter()
        .take(max_lines)
        .map(|e| {
            let color = theme.event_color(&e.event_type);
            let path_id = if e.path_id > 0 {
                format!(" path_id={}", e.path_id)
            } else {
                String::new()
            };
            Line::from(vec![
                Span::styled(
                    format!("[{}] ", e.timestamp),
                    Style::default().fg(theme.text_dim),
                ),
                Span::styled(format!("{:<10}", e.event_type), Style::default().fg(color)),
                Span::styled(format!("{:<20}", e.prefix), Style::default().fg(theme.text)),
                Span::styled(
                    format!("from {}{}", e.peer_address, path_id),
                    Style::default().fg(theme.text_dim),
                ),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    let elapsed = app.last_poll.elapsed().as_secs();
    let ago = if elapsed == 0 {
        "just now".to_string()
    } else {
        format!("{elapsed}s ago")
    };

    let events_label = if app.show_events {
        "e Events(on)"
    } else {
        "e Events"
    };

    let left = format!(" q Quit | h Help | {events_label} | s Sort | Enter Detail");
    let right = format!("Last poll: {ago} ");

    let available = area.width as usize;
    let pad = available.saturating_sub(left.len() + right.len());
    let line = format!("{left}{:pad$}{right}", "");

    let paragraph = Paragraph::new(Line::from(vec![Span::styled(
        line,
        Style::default().fg(theme.text_dim),
    )]));
    f.render_widget(paragraph, area);
}

fn draw_peer_detail(f: &mut Frame, app: &mut App, address: &str, theme: &Theme) {
    let Some(neighbor) = app.neighbor(address) else {
        app.view = View::PeerTable;
        return;
    };

    let cfg = neighbor.config.as_ref();
    let title = format!(" Peer Detail: {address} ");

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));

    let inner = block.inner(f.area());
    f.render_widget(block, f.area());

    let state_label = format_state_with_stale(neighbor.state, neighbor.stale);
    let state_color = theme.state_color_with_stale(neighbor.state, neighbor.stale);
    let families = cfg
        .map(|c| {
            c.families
                .iter()
                .map(|f| format_family(crate::output::parse_family(f).unwrap_or(0)))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();

    let rate = app.peer_update_rate(address);

    let lines = vec![
        Line::from(vec![
            Span::styled("  Neighbor:       ", Style::default().fg(theme.text_dim)),
            Span::styled(address.to_string(), Style::default().fg(theme.header_fg)),
        ]),
        Line::from(vec![
            Span::styled("  Remote ASN:     ", Style::default().fg(theme.text_dim)),
            Span::styled(
                cfg.map(|c| c.remote_asn.to_string()).unwrap_or_default(),
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Description:    ", Style::default().fg(theme.text_dim)),
            Span::styled(
                cfg.map(|c| c.description.as_str()).unwrap_or(""),
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  State:          ", Style::default().fg(theme.text_dim)),
            Span::styled(state_label, Style::default().fg(state_color)),
        ]),
        Line::from(vec![
            Span::styled("  Uptime:         ", Style::default().fg(theme.text_dim)),
            Span::styled(
                format_duration(neighbor.uptime_seconds),
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Families:       ", Style::default().fg(theme.text_dim)),
            Span::styled(families, Style::default().fg(theme.text)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Prefixes Rx:    ", Style::default().fg(theme.text_dim)),
            Span::styled(
                format_number(neighbor.prefixes_received),
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Prefixes Tx:    ", Style::default().fg(theme.text_dim)),
            Span::styled(
                format_number(neighbor.prefixes_sent),
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Updates Rx:     ", Style::default().fg(theme.text_dim)),
            Span::styled(
                format_number(neighbor.updates_received),
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Updates Tx:     ", Style::default().fg(theme.text_dim)),
            Span::styled(
                format_number(neighbor.updates_sent),
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Update Rate:    ", Style::default().fg(theme.text_dim)),
            Span::styled(format!("{rate:.1}/s"), Style::default().fg(theme.text)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Notifications Rx: ", Style::default().fg(theme.text_dim)),
            Span::styled(
                neighbor.notifications_received.to_string(),
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Notifications Tx: ", Style::default().fg(theme.text_dim)),
            Span::styled(
                neighbor.notifications_sent.to_string(),
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Flap Count:     ", Style::default().fg(theme.text_dim)),
            Span::styled(
                neighbor.flap_count.to_string(),
                Style::default().fg(if neighbor.flap_count > 0 {
                    theme.state_down
                } else {
                    theme.text
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Hold Time:      ", Style::default().fg(theme.text_dim)),
            Span::styled(
                format!("{}s", cfg.map(|c| c.hold_time).unwrap_or(0)),
                Style::default().fg(theme.text),
            ),
        ]),
    ];

    let mut all_lines = lines;
    if !neighbor.last_error.is_empty() {
        all_lines.push(Line::from(vec![
            Span::styled("  Last Error:     ", Style::default().fg(theme.text_dim)),
            Span::styled(
                neighbor.last_error.clone(),
                Style::default().fg(theme.error),
            ),
        ]));
    }

    all_lines.push(Line::from(""));
    all_lines.push(Line::from(Span::styled(
        "  Press Esc to go back",
        Style::default().fg(theme.text_dim),
    )));

    let paragraph = Paragraph::new(all_lines).wrap(Wrap { trim: false });
    f.render_widget(paragraph, inner);
}

fn draw_help_overlay(f: &mut Frame, theme: &Theme) {
    let area = centered_rect(50, 60, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .title(" Help ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.accent));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  rbgp top — Live TUI Dashboard",
            Style::default()
                .fg(theme.header_fg)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  q / Ctrl-C  ", Style::default().fg(theme.accent)),
            Span::styled("Quit", Style::default().fg(theme.text)),
        ]),
        Line::from(vec![
            Span::styled("  h           ", Style::default().fg(theme.accent)),
            Span::styled("Toggle this help", Style::default().fg(theme.text)),
        ]),
        Line::from(vec![
            Span::styled("  e           ", Style::default().fg(theme.accent)),
            Span::styled("Toggle route events panel", Style::default().fg(theme.text)),
        ]),
        Line::from(vec![
            Span::styled("  s           ", Style::default().fg(theme.accent)),
            Span::styled("Cycle sort column", Style::default().fg(theme.text)),
        ]),
        Line::from(vec![
            Span::styled("  S           ", Style::default().fg(theme.accent)),
            Span::styled("Reverse sort direction", Style::default().fg(theme.text)),
        ]),
        Line::from(vec![
            Span::styled("  j / Down    ", Style::default().fg(theme.accent)),
            Span::styled("Select next peer", Style::default().fg(theme.text)),
        ]),
        Line::from(vec![
            Span::styled("  k / Up      ", Style::default().fg(theme.accent)),
            Span::styled("Select previous peer", Style::default().fg(theme.text)),
        ]),
        Line::from(vec![
            Span::styled("  Enter       ", Style::default().fg(theme.accent)),
            Span::styled("Show peer detail", Style::default().fg(theme.text)),
        ]),
        Line::from(vec![
            Span::styled("  Esc         ", Style::default().fg(theme.accent)),
            Span::styled("Back to peer table", Style::default().fg(theme.text)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Press any key to close",
            Style::default().fg(theme.text_dim),
        )),
    ];

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(popup_layout[1])[1]
}

fn format_number(n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{GlobalState, HealthResponse, NeighborConfig, NeighborState};
    use crate::tui::data::DataSnapshot;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(12345), "12,345");
        assert_eq!(format_number(1234567), "1,234,567");
    }

    fn snapshot(neighbors: Vec<NeighborState>, freshness: Freshness) -> DataSnapshot {
        DataSnapshot {
            global: Some(GlobalState {
                asn: 65001,
                router_id: "10.0.0.1".into(),
                ..Default::default()
            }),
            global_freshness: Freshness::Fresh,
            health: Some(HealthResponse {
                healthy: true,
                ..Default::default()
            }),
            health_fresh: true,
            neighbors,
            neighbors_freshness: freshness,
            dynamic_range_count: Some(0),
            dynamic_ranges_freshness: Freshness::Fresh,
            rpki_vrp_count: None,
            metrics_freshness: Freshness::Fresh,
            error: None,
        }
    }

    fn rendered_snapshot(snapshot: DataSnapshot) -> String {
        let mut app = App::new();
        app.on_data(snapshot);
        let mut terminal = Terminal::new(TestBackend::new(130, 8)).unwrap();
        terminal
            .draw(|frame| draw(frame, &mut app, &Theme::default()))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    fn rendered_peer_table(with_neighbor: bool, freshness: Freshness) -> String {
        let neighbors = if with_neighbor {
            vec![NeighborState {
                config: Some(NeighborConfig {
                    address: "fe80::1".into(),
                    interface: "eth0".into(),
                    remote_asn: 64512,
                    description: "route-server member".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }]
        } else {
            Vec::new()
        };
        let mut app = App::new();
        app.on_data(snapshot(neighbors, Freshness::Fresh));
        if freshness != Freshness::Fresh {
            app.on_data(snapshot(Vec::new(), freshness));
        }
        let mut terminal = Terminal::new(TestBackend::new(130, 8)).unwrap();
        terminal
            .draw(|frame| draw(frame, &mut app, &Theme::default()))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    /// Red proof: removing the ninth header loses its rendered label.
    #[test]
    fn peer_table_labels_description_column() {
        assert!(rendered_peer_table(true, Freshness::Stale).contains("Description"));
    }

    /// Red proof: rendering the bare address removes row interface scope.
    #[test]
    fn peer_table_renders_scoped_neighbor_identity() {
        let rendered = rendered_peer_table(true, Freshness::Stale);
        assert!(rendered.contains("fe80::1%eth0"));
    }

    /// Red proof: removing the stale label makes retained data look fresh.
    #[test]
    fn header_labels_retained_neighbor_roster_as_stale() {
        let rendered = rendered_peer_table(true, Freshness::Stale);
        assert!(rendered.contains("stale: neighbors"));
    }

    /// Red proof: collapsing unavailable into stale mislabels a first failure.
    #[test]
    fn header_distinguishes_first_neighbor_failure_from_stale_data() {
        let rendered = rendered_peer_table(false, Freshness::Unavailable);
        assert!(rendered.contains("neighbors unavailable"));
        assert!(!rendered.contains("stale: neighbors"));
    }

    #[test]
    fn header_labels_global_unavailable_without_disconnect() {
        let mut data = snapshot(Vec::new(), Freshness::Unavailable);
        data.global = None;
        data.global_freshness = Freshness::Unavailable;

        let rendered = rendered_snapshot(data);

        assert!(rendered.contains("global unavailable"));
        assert!(rendered.contains("connected"));
    }

    #[test]
    fn header_labels_initial_rpki_failure_without_disconnect() {
        let mut data = snapshot(Vec::new(), Freshness::Unavailable);
        data.metrics_freshness = Freshness::Unavailable;

        let rendered = rendered_snapshot(data);

        assert!(rendered.contains("RPKI unavailable"));
        assert!(rendered.contains("connected"));
    }

    #[test]
    fn header_labels_retained_rpki_count_as_stale_without_disconnect() {
        let mut data = snapshot(Vec::new(), Freshness::Unavailable);
        data.rpki_vrp_count = Some(15);
        data.metrics_freshness = Freshness::Stale;

        let rendered = rendered_snapshot(data);

        assert!(rendered.contains("VRPs 15"));
        assert!(rendered.contains("stale: RPKI"));
        assert!(rendered.contains("connected"));
    }

    #[test]
    fn header_is_quiet_after_success_without_rpki_family() {
        let data = snapshot(Vec::new(), Freshness::Unavailable);
        let rendered = rendered_snapshot(data);

        assert!(!rendered.contains("RPKI unavailable"));
        assert!(!rendered.contains("stale: RPKI"));
        assert!(!rendered.contains("VRPs"));
        assert!(rendered.contains("connected"));

        let mut data = snapshot(Vec::new(), Freshness::Unavailable);
        data.metrics_freshness = Freshness::Stale;
        let rendered = rendered_snapshot(data);
        assert!(!rendered.contains("RPKI"));
        assert!(!rendered.contains("VRPs"));
    }

    #[test]
    fn empty_roster_renders_fresh_dynamic_range_count_and_proven_zero() {
        let mut configured = snapshot(Vec::new(), Freshness::Fresh);
        configured.dynamic_range_count = Some(2);
        assert!(
            rendered_snapshot(configured).contains("0 active peers; 2 dynamic ranges configured")
        );

        let unconfigured = rendered_snapshot(snapshot(Vec::new(), Freshness::Fresh));
        assert!(unconfigured.contains("0 active peers; no peers or dynamic ranges configured"));
    }

    #[test]
    fn initial_dynamic_range_failure_is_unavailable_but_connected() {
        let mut data = snapshot(Vec::new(), Freshness::Fresh);
        data.dynamic_range_count = None;
        data.dynamic_ranges_freshness = Freshness::Unavailable;

        let rendered = rendered_snapshot(data);

        assert!(rendered.contains("0 active peers; dynamic ranges unavailable"));
        assert!(rendered.contains("connected"));
        assert!(!rendered.contains("disconnected"));
    }

    #[test]
    fn stale_dynamic_range_count_retains_nonzero_and_zero_without_false_proof() {
        for (count, expected) in [
            (
                2,
                "0 active peers; last known dynamic range count: 2 (stale)",
            ),
            (
                0,
                "0 active peers; last known dynamic range count: 0 (stale)",
            ),
        ] {
            let mut data = snapshot(Vec::new(), Freshness::Fresh);
            data.dynamic_range_count = Some(count);
            data.dynamic_ranges_freshness = Freshness::Stale;
            let rendered = rendered_snapshot(data);
            assert!(rendered.contains(expected));
            if count == 0 {
                assert!(!rendered.contains("no peers or dynamic ranges configured"));
            }
        }
    }
}
