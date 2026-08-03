use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table};

use crate::commands::neighbor::{
    negotiated_families_label, negotiation_status_label, next_hop_ownership_label,
    optional_seconds_label, rfc8212_policy_status_label,
};
use crate::output::{format_duration, format_state_with_stale, neighbor_source_label};
use crate::tui::app::{App, SortColumn, View, neighbor_key};
use crate::tui::data::{Freshness, RouteEventEntry, RouteEventKind};
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

    let mut lines = Vec::new();
    if let Some(status) = &app.route_event_stream_status {
        lines.push(Line::styled(
            format!("warning: {status}"),
            Style::default().fg(theme.error),
        ));
    }
    lines.extend(
        app.route_events
            .iter()
            .take((inner.height as usize).saturating_sub(lines.len()))
            .map(|e| {
                let color = theme.event_color(&e.event_type);
                Line::from(vec![
                    Span::styled(
                        format!("[{}] ", e.timestamp),
                        Style::default().fg(theme.text_dim),
                    ),
                    Span::styled(format!("{:<10}", e.event_type), Style::default().fg(color)),
                    Span::styled(format!("{:<20}", e.prefix), Style::default().fg(theme.text)),
                    Span::styled(route_event_context(e), Style::default().fg(theme.text_dim)),
                ])
            }),
    );

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn route_event_context(event: &RouteEventEntry) -> String {
    if matches!(&event.kind, RouteEventKind::StreamLag) {
        let reason = if event.reason.is_empty() {
            String::new()
        } else {
            format!(" reason={}", event.reason)
        };
        return format!("missed={}{}", event.missed_count, reason);
    }

    let mut fields = vec![format!("from {}", event.peer_address)];
    if !event.previous_peer_address.is_empty() {
        fields.push(format!("previous={}", event.previous_peer_address));
    }
    if !event.target_peer_address.is_empty() {
        fields.push(format!("to={}", event.target_peer_address));
    }
    if !event.reason.is_empty() {
        fields.push(format!("reason={}", event.reason));
    }
    if event.path_id > 0 {
        fields.push(format!("path_id={}", event.path_id));
    }
    fields.join(" ")
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
        app.return_to_table();
        return;
    };

    let cfg = neighbor.config.as_ref();
    let title = format!(" Peer Detail: {address} | Esc back | j/k scroll ");

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));

    let inner = block.inner(f.area());
    f.render_widget(block, f.area());

    let state_label = format_state_with_stale(neighbor.state, neighbor.stale);
    let state_color = theme.state_color_with_stale(neighbor.state, neighbor.stale);
    let rate = app.peer_update_rate(address);
    let negotiation = negotiation_status_label(neighbor);
    let negotiated_hold = neighbor.negotiated_session.as_ref().map_or_else(
        || negotiation.to_string(),
        |session| optional_seconds_label(session.hold_time_seconds),
    );
    let negotiated_families = neighbor.negotiated_session.as_ref().map_or_else(
        || negotiation.to_string(),
        |session| negotiated_families_label(&session.families),
    );
    let configured_hold = cfg.map_or_else(
        || "unknown".to_string(),
        |config| match config.hold_time {
            0 => "default (no override)".to_string(),
            seconds => format!("{seconds}s"),
        },
    );
    let configured_families = cfg.map_or_else(
        || "unknown".to_string(),
        |config| {
            if config.families.is_empty() {
                "ipv4_unicast (default)".to_string()
            } else {
                negotiated_families_label(&config.families)
            }
        },
    );
    let peer_group = match cfg.map(|config| config.peer_group.as_str()) {
        None => "unknown",
        Some("") => "none",
        Some(group) => group,
    };
    let update_group = if neighbor.update_group.is_empty() {
        "unknown (not exposed or no outbound registration)"
    } else {
        &neighbor.update_group
    };
    let rr_client = if neighbor.route_reflector_client {
        "true"
    } else {
        "false (not configured or not exposed by older daemon)"
    };
    let route_server_client = cfg.map_or_else(
        || "unknown".to_string(),
        |config| config.route_server_client.to_string(),
    );
    let slow_peer = if neighbor.slow_peer {
        "true (queue backlog signal; not a session-health verdict)"
    } else {
        "false (not flagged or not exposed by older daemon; not a session-health verdict)"
    };

    let row = |label: &str, value: String, value_style: Style| {
        Line::from(vec![
            Span::styled(
                format!("  {label:<27}"),
                Style::default().fg(theme.text_dim),
            ),
            Span::styled(value, value_style),
        ])
    };
    let text = Style::default().fg(theme.text);
    let section = |label: &str| {
        Line::from(Span::styled(
            format!("  {label}"),
            Style::default()
                .fg(theme.header_fg)
                .add_modifier(Modifier::BOLD),
        ))
    };

    let mut all_lines = vec![
        row(
            "Neighbor:",
            address.to_string(),
            Style::default().fg(theme.header_fg),
        ),
        row(
            "Remote ASN:",
            cfg.map(|config| config.remote_asn.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            text,
        ),
        row(
            "Description:",
            cfg.map(|config| config.description.clone())
                .unwrap_or_default(),
            text,
        ),
        row("Source:", neighbor_source_label(neighbor), text),
        row(
            "State:",
            state_label.to_string(),
            Style::default().fg(state_color),
        ),
        row("Uptime:", format_duration(neighbor.uptime_seconds), text),
        row("Configured Hold Time:", configured_hold, text),
        row("Negotiation:", negotiation.to_string(), text),
        row("Negotiated Hold Time:", negotiated_hold, text),
        row("Configured Families:", configured_families, text),
        row("Negotiated Families:", negotiated_families, text),
        Line::from(""),
        row(
            "Prefixes Rx:",
            format_number(neighbor.prefixes_received),
            text,
        ),
        row("Prefixes Tx:", format_number(neighbor.prefixes_sent), text),
        row(
            "Updates Rx:",
            format_number(neighbor.updates_received),
            text,
        ),
        row("Updates Tx:", format_number(neighbor.updates_sent), text),
        row("Update Rate:", format!("{rate:.1}/s"), text),
        row(
            "Notifications Rx:",
            neighbor.notifications_received.to_string(),
            text,
        ),
        row(
            "Notifications Tx:",
            neighbor.notifications_sent.to_string(),
            text,
        ),
        row(
            "Flap Count:",
            neighbor.flap_count.to_string(),
            Style::default().fg(if neighbor.flap_count > 0 {
                theme.state_down
            } else {
                theme.text
            }),
        ),
    ];
    if !neighbor.last_error.is_empty() {
        all_lines.push(row(
            "Last Error:",
            neighbor.last_error.clone(),
            Style::default().fg(theme.error),
        ));
    }
    all_lines.push(Line::from(""));
    all_lines.extend([
        row("Peer Group:", peer_group.to_string(), text),
        row("Update Group:", update_group.to_string(), text),
        row("RR Client:", rr_client.to_string(), text),
        row("Route Server Client:", route_server_client, text),
        row("Slow Peer:", slow_peer.to_string(), text),
        Line::from(""),
        section("Effective Posture:"),
    ]);
    if let Some(posture) = neighbor.effective_posture.as_ref() {
        all_lines.extend([
            row(
                "  NEXT_HOP Ownership:",
                next_hop_ownership_label(posture.next_hop_ownership).to_string(),
                text,
            ),
            row(
                "  Interpret RFC 1997:",
                posture.interpret_rfc1997.to_string(),
                text,
            ),
            row(
                "  RS Control Communities:",
                posture.rs_control_communities.to_string(),
                text,
            ),
            row(
                "  ORR Vantage:",
                posture.orr_vantage.as_deref().unwrap_or("none").to_string(),
                text,
            ),
        ]);
    } else {
        for label in [
            "  NEXT_HOP Ownership:",
            "  Interpret RFC 1997:",
            "  RS Control Communities:",
            "  ORR Vantage:",
        ] {
            all_lines.push(row(
                label,
                "unknown (not exposed by daemon)".to_string(),
                text,
            ));
        }
    }
    all_lines.extend([
        Line::from(""),
        section("RFC 8212 Policy:"),
        row(
            "  Import:",
            rfc8212_policy_status_label(neighbor.rfc8212_import_policy).to_string(),
            text,
        ),
        row(
            "  Export:",
            rfc8212_policy_status_label(neighbor.rfc8212_export_policy).to_string(),
            text,
        ),
        Line::from(""),
    ]);
    if neighbor.outbound_prefix_limits.is_empty() {
        all_lines.push(row(
            "Outbound Prefix Limits:",
            "unknown (not exposed or no outbound registration)".to_string(),
            text,
        ));
    } else {
        all_lines.push(section("Outbound Prefix Limits:"));
        for limit in &neighbor.outbound_prefix_limits {
            let limit_label = limit
                .limit
                .map_or_else(|| "unlimited".to_string(), |value| value.to_string());
            let headroom = match (limit.limit, limit.headroom) {
                (None, _) => "not applicable".to_string(),
                (Some(_), Some(value)) => value.to_string(),
                (Some(_), None) => "unknown".to_string(),
            };
            let reason = limit
                .reason
                .as_deref()
                .map_or_else(String::new, |reason| format!(" reason={reason}"));
            all_lines.push(Line::from(Span::styled(
                format!(
                    "  Outbound {}: usage={} limit={limit_label} headroom={headroom} blocking={}{}",
                    limit.family, limit.usage, limit.blocking, reason
                ),
                Style::default().fg(if limit.blocking {
                    theme.error
                } else {
                    theme.text
                }),
            )));
        }
    }

    app.set_detail_layout(all_lines.len(), usize::from(inner.height));
    let scroll = u16::try_from(app.detail_scroll).unwrap_or(u16::MAX);
    let paragraph = Paragraph::new(all_lines).scroll((scroll, 0));
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

    /// Red proof: restoring the source-only event row or storing the degraded
    /// warning in the bounded route rows removes these strings from the real
    /// rendered event panel.
    #[test]
    fn event_panel_test_backend_renders_context_lag_and_degraded_status() {
        let mut app = App::new();
        app.show_events = true;
        app.on_data(snapshot(Vec::new(), Freshness::Fresh));
        app.on_route_event(crate::tui::data::RouteEventUpdate::StreamStatus(Some(
            "DEGRADED: WatchEvents unsupported; using legacy WatchRoutes; missed-event counts unavailable".into(),
        )));
        let lag = |missed_count| RouteEventEntry {
            kind: RouteEventKind::StreamLag,
            timestamp: "12:00:01".into(),
            event_type: "stream_lagged".into(),
            prefix: String::new(),
            peer_address: String::new(),
            previous_peer_address: String::new(),
            target_peer_address: String::new(),
            reason: "receiver_lagged".into(),
            path_id: 0,
            missed_count,
        };
        app.on_route_event(crate::tui::data::RouteEventUpdate::Event(lag(7)));
        app.on_route_event(crate::tui::data::RouteEventUpdate::Event(lag(0)));
        app.on_route_event(crate::tui::data::RouteEventUpdate::Event(RouteEventEntry {
            kind: RouteEventKind::Route,
            timestamp: "12:00:00".into(),
            event_type: "policy_filtered".into(),
            prefix: "203.0.113.0/24".into(),
            peer_address: "192.0.2.1".into(),
            previous_peer_address: "192.0.2.2".into(),
            target_peer_address: "192.0.2.3".into(),
            reason: "policy_denied".into(),
            path_id: 77,
            missed_count: 0,
        }));
        let mut terminal = Terminal::new(TestBackend::new(180, 18)).unwrap();
        terminal
            .draw(|frame| draw(frame, &mut app, &Theme::default()))
            .unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();

        assert!(rendered.contains("DEGRADED: WatchEvents unsupported"));
        assert!(rendered.contains(
            "from 192.0.2.1 previous=192.0.2.2 to=192.0.2.3 reason=policy_denied path_id=77"
        ));
        assert!(rendered.contains("missed=7 reason=receiver_lagged"));
        assert!(rendered.contains("missed=0 reason=receiver_lagged"));
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

    fn safety_neighbor() -> NeighborState {
        NeighborState {
            config: Some(NeighborConfig {
                address: "192.0.2.2".into(),
                remote_asn: 65002,
                description: "route-server and reflector client".into(),
                hold_time: 90,
                families: vec!["ipv4_unicast".into(), "ipv6_unicast".into()],
                peer_group: "edge-clients".into(),
                route_server_client: true,
                ..Default::default()
            }),
            state: crate::proto::SessionState::Established as i32,
            uptime_seconds: 3600,
            prefixes_received: 11,
            prefixes_sent: 12,
            updates_received: 13,
            updates_sent: 14,
            notifications_received: 1,
            notifications_sent: 2,
            flap_count: 3,
            route_reflector_client: true,
            slow_peer: true,
            is_dynamic: true,
            accepted_dynamic_range: Some(crate::proto::AcceptedDynamicNeighborRange {
                prefix: "192.0.2.0/24".into(),
                peer_group: "edge-clients".into(),
            }),
            update_group: "group:7".into(),
            negotiation_available: Some(true),
            negotiated_session: Some(crate::proto::NegotiatedSessionState {
                hold_time_seconds: Some(30),
                families: vec!["ipv4_unicast".into()],
                ..Default::default()
            }),
            effective_posture: Some(crate::proto::EffectiveNeighborPosture {
                next_hop_ownership: crate::proto::NextHopOwnershipMode::StrictPeer as i32,
                interpret_rfc1997: true,
                rs_control_communities: false,
                orr_vantage: Some("pop-a".into()),
            }),
            rfc8212_import_policy: crate::proto::Rfc8212PolicyStatus::Present as i32,
            rfc8212_export_policy: crate::proto::Rfc8212PolicyStatus::Missing as i32,
            outbound_prefix_limits: vec![
                crate::proto::OutboundPrefixLimitState {
                    family: "ipv4_unicast".into(),
                    usage: 7,
                    limit: None,
                    headroom: None,
                    blocking: false,
                    reason: None,
                },
                crate::proto::OutboundPrefixLimitState {
                    family: "ipv6_unicast".into(),
                    usage: 50,
                    limit: Some(50),
                    headroom: Some(0),
                    blocking: true,
                    reason: Some("outbound_prefix_limit_reached".into()),
                },
            ],
            ..Default::default()
        }
    }

    fn rendered_detail(app: &mut App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| draw(frame, app, &Theme::default()))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .chunks(usize::from(width))
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn assert_detail_row(rendered: &str, label: &str, expected: &str) {
        let line = rendered
            .lines()
            .find(|line| line.contains(label))
            .unwrap_or_else(|| panic!("missing detail row {label:?}\n{rendered}"));
        assert!(
            line.contains(expected),
            "detail row {label:?} did not contain {expected:?}: {line:?}"
        );
    }

    /// Mutation receipts: changing the production older-daemon negotiation
    /// label to plain `unknown`, rendering zero hold as `0s`, or rendering the
    /// empty family sentinel as `none` makes the old-daemon/default half red.
    #[test]
    fn peer_detail_pins_rich_safety_state_and_rolling_upgrade_unknowns() {
        let mut rich = App::new();
        rich.on_data(snapshot(vec![safety_neighbor()], Freshness::Fresh));
        rich.view = View::PeerDetail("192.0.2.2".into());
        let rendered = rendered_detail(&mut rich, 130, 50);

        for (label, expected) in [
            ("Configured Hold Time:", "90s"),
            ("Negotiated Hold Time:", "30s"),
            ("Configured Families:", "ipv4_unicast, ipv6_unicast"),
            ("Negotiated Families:", "ipv4_unicast"),
            ("Source:", "dynamic (192.0.2.0/24, group edge-clients)"),
            ("Peer Group:", "edge-clients"),
            ("Update Group:", "group:7"),
            ("RR Client:", "true"),
            ("Route Server Client:", "true"),
            (
                "Slow Peer:",
                "true (queue backlog signal; not a session-health verdict)",
            ),
            ("NEXT_HOP Ownership:", "strict_peer"),
            ("Interpret RFC 1997:", "true"),
            ("RS Control Communities:", "false"),
            ("ORR Vantage:", "pop-a"),
            ("Import:", "present"),
            ("Export:", "missing"),
            (
                "Outbound ipv4_unicast:",
                "usage=7 limit=unlimited headroom=not applicable blocking=false",
            ),
            (
                "Outbound ipv6_unicast:",
                "usage=50 limit=50 headroom=0 blocking=true reason=outbound_prefix_limit_reached",
            ),
        ] {
            assert_detail_row(&rendered, label, expected);
        }
        assert!(rendered.contains("Effective Posture:"));
        assert!(rendered.contains("RFC 8212 Policy:"));
        assert!(rendered.contains("Outbound Prefix Limits:"));

        let old_daemon = NeighborState {
            config: Some(NeighborConfig {
                address: "198.51.100.2".into(),
                remote_asn: 65003,
                hold_time: 0,
                families: Vec::new(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut old = App::new();
        old.on_data(snapshot(vec![old_daemon], Freshness::Fresh));
        old.view = View::PeerDetail("198.51.100.2".into());
        let rendered = rendered_detail(&mut old, 130, 50);
        assert_detail_row(&rendered, "Configured Hold Time:", "default (no override)");
        assert_detail_row(&rendered, "Configured Families:", "ipv4_unicast (default)");
        for label in ["Negotiated Hold Time:", "Negotiated Families:"] {
            assert_detail_row(&rendered, label, "unknown (not exposed by daemon)");
        }
        assert_detail_row(
            &rendered,
            "Update Group:",
            "unknown (not exposed or no outbound registration)",
        );
        assert_detail_row(
            &rendered,
            "Outbound Prefix Limits:",
            "unknown (not exposed or no outbound registration)",
        );
        for label in [
            "NEXT_HOP Ownership:",
            "Interpret RFC 1997:",
            "RS Control Communities:",
            "ORR Vantage:",
        ] {
            assert_detail_row(&rendered, label, "unknown (not exposed by daemon)");
        }
        assert_detail_row(
            &rendered,
            "RR Client:",
            "false (not configured or not exposed by older daemon)",
        );
        assert_detail_row(&rendered, "Route Server Client:", "false");
        assert_detail_row(
            &rendered,
            "Slow Peer:",
            "false (not flagged or not exposed by older daemon; not a session-health verdict)",
        );
        assert_detail_row(&rendered, "Import:", "unknown");
        assert_detail_row(&rendered, "Export:", "unknown");
    }

    /// Mutation receipt: forcing the production paragraph scroll offset to zero
    /// makes the blocking-row assertion red. Re-enabling row wrapping also
    /// makes it red because the long description consumes unreported visual
    /// rows before the final safety row.
    #[test]
    fn peer_detail_130x8_reaches_final_blocking_row_without_wrapping() {
        let mut neighbor = safety_neighbor();
        neighbor.config.as_mut().unwrap().description = "long-description-".repeat(20);
        let final_row = "Outbound ipv6_unicast: usage=50 limit=50 headroom=0 blocking=true";
        let mut app = App::new();
        app.on_data(snapshot(vec![neighbor], Freshness::Fresh));
        app.view = View::PeerDetail("192.0.2.2".into());

        let initial = rendered_detail(&mut app, 130, 8);
        assert!(!initial.contains(final_row));
        assert_eq!(app.detail_page_height, 6);
        assert!(app.detail_max_scroll > app.detail_page_height);

        app.on_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::End,
            crossterm::event::KeyModifiers::NONE,
        ));
        let moved = rendered_detail(&mut app, 130, 8);
        assert!(moved.contains(final_row), "{moved}");
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
