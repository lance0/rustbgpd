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
use crate::tui::app::{
    App, EditorMode, ExplainState, PrefixEditor, RibPageState, SortColumn, View, neighbor_key,
};
use crate::tui::data::{Freshness, RibFamily, RouteEventEntry, RouteEventKind};
use crate::tui::theme::Theme;

pub fn draw(f: &mut Frame, app: &mut App, theme: &Theme) {
    match app.view.clone() {
        View::PeerTable => draw_main(f, app, theme),
        View::PeerDetail(address) => draw_peer_detail(f, app, &address, theme),
        View::RouteExplorer(peer) => draw_route_explorer(f, app, &peer, theme),
        View::AdvertisedExplain(peer) => draw_advertised_explain(f, app, &peer, theme),
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
    let title = format!(" Peer Detail: {address} | r Best RIB | Esc back | j/k scroll ");

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
    let local_address = neighbor.negotiated_session.as_ref().map_or_else(
        || negotiation.to_string(),
        |session| {
            session
                .local_address
                .clone()
                .unwrap_or_else(|| "unknown".to_string())
        },
    );
    let keepalive = neighbor.negotiated_session.as_ref().map_or_else(
        || negotiation.to_string(),
        |session| optional_seconds_label(session.keepalive_interval_seconds),
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
        row("Local Address:", local_address, text),
        row("Negotiated Hold Time:", negotiated_hold, text),
        row("Keepalive Interval:", keepalive, text),
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

fn draw_route_explorer(f: &mut Frame, app: &mut App, peer: &str, theme: &Theme) {
    let scope = if app.rib_view.peer_scoped() {
        format!("peer {peer}")
    } else {
        format!("global | explain target {peer}")
    };
    let filter = app.rib_filter.map_or_else(
        || "no filter".to_string(),
        |filter| format!("filter {}", filter.label()),
    );
    let block = Block::default()
        .title(format!(
            " Routes: {} | {scope} | {} | {filter} ",
            app.rib_view.label(),
            app.rib_family.label()
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));
    let inner = block.inner(f.area());
    f.render_widget(block, f.area());
    let chunks = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(inner);
    let (body, status_area, keys_area) = (chunks[0], chunks[1], chunks[2]);
    // One header row; the rest are data rows Space/PgDn move across.
    app.set_rib_layout(usize::from(body.height.saturating_sub(1)));

    let dim = Style::default().fg(theme.text_dim);
    let header_style = Style::default()
        .fg(theme.header_fg)
        .add_modifier(Modifier::BOLD);
    let highlight = Style::default()
        .fg(theme.highlight)
        .add_modifier(Modifier::BOLD);
    let notice = app
        .rib_notice
        .map_or(String::new(), |notice| format!(" | {notice}"));
    let row = app.rib_table_state.selected().map_or(0, |i| i + 1);
    let view_lower = app.rib_view.label().to_ascii_lowercase();

    match app.rib_page.as_ref() {
        Some(RibPageState::Loading) | None => {
            f.render_widget(Paragraph::new("Loading routes..."), body)
        }
        Some(RibPageState::Error(message)) => f.render_widget(
            Paragraph::new(message.as_str()).style(Style::default().fg(theme.error)),
            body,
        ),
        Some(RibPageState::Ready(page)) => {
            let status = format!(
                "row {row}/{} | server page {} | total {} | snapshot {}{notice}",
                page.routes.len(),
                app.rib_previous_tokens.len() + 1,
                page.total_count,
                page.page_version.as_ref().map_or_else(
                    || "unfenced".to_string(),
                    |version| format!("{}.{}", version.epoch, version.generation)
                ),
            );
            if page.routes.is_empty() {
                let message = match (page.total_count, app.rib_filter) {
                    (0, Some(filter)) => {
                        format!("No {view_lower} routes match {}", filter.label())
                    }
                    (0, None) => format!("No {view_lower} routes"),
                    _ => "Empty page".to_string(),
                };
                f.render_widget(Paragraph::new(message), body);
            } else {
                let rows = page.routes.iter().map(|route| {
                    Row::new(vec![
                        Cell::from(format!("{}/{}", route.prefix, route.prefix_length)),
                        Cell::from(route.next_hop.clone()),
                        Cell::from(route.peer_address.clone()),
                        Cell::from(
                            route
                                .as_path
                                .iter()
                                .map(u32::to_string)
                                .collect::<Vec<_>>()
                                .join(" "),
                        ),
                        Cell::from(optional_u32(route.local_pref_attr)),
                        Cell::from(optional_u32(route.med_attr)),
                        Cell::from(route.validation_state.clone()),
                        Cell::from(route.aspa_state.clone()),
                    ])
                });
                let table = Table::new(
                    rows,
                    [
                        Constraint::Min(16),
                        Constraint::Min(13),
                        Constraint::Min(13),
                        Constraint::Min(12),
                        Constraint::Length(9),
                        Constraint::Length(7),
                        Constraint::Length(9),
                        Constraint::Length(8),
                    ],
                )
                .header(
                    Row::new([
                        "Prefix",
                        "Next Hop",
                        "Source Peer",
                        "AS Path",
                        "LocalPref",
                        "MED",
                        "RPKI",
                        "ASPA",
                    ])
                    .style(header_style),
                )
                .row_highlight_style(highlight)
                .highlight_symbol("> ");
                f.render_stateful_widget(table, body, &mut app.rib_table_state);
            }
            f.render_widget(Paragraph::new(status).style(dim), status_area);
        }
        Some(RibPageState::Rejected { page, retained }) => {
            let evictions = page
                .evictions_since_reset
                .map_or_else(|| "unknown".to_string(), |count| count.to_string());
            let status = format!(
                "row {row}/{} | page 1 of 1 | matched {} of {retained} retained (cap {}) | evictions {evictions}{notice}",
                page.routes.len(),
                page.routes.len(),
                page.capacity,
            );
            if !page.retention_enabled {
                f.render_widget(
                    Paragraph::new(
                        "Rejected-route retention is disabled for this peer ([policy.reject_retention])",
                    ),
                    body,
                );
            } else if page.routes.is_empty() {
                let message = if *retained == 0 {
                    "No retained rejected routes".to_string()
                } else {
                    format!(
                        "No retained rejected routes match {}{}",
                        app.rib_family.label(),
                        app.rib_filter
                            .map_or(String::new(), |filter| format!(" {}", filter.label()))
                    )
                };
                f.render_widget(Paragraph::new(message), body);
            } else {
                let rows = page.routes.iter().map(|route| {
                    Row::new(vec![
                        Cell::from(format!("{}/{}", route.prefix, route.prefix_length)),
                        Cell::from(route.path_id.to_string()),
                        Cell::from(route.reason.clone()),
                        Cell::from(rejected_cell(&route.reason_detail)),
                        Cell::from(rejected_cell(&route.next_hop)),
                        Cell::from(rejected_cell(&route.rpki_validation)),
                        Cell::from(rejected_cell(&route.aspa_validation)),
                        Cell::from(route.as_path.clone()),
                    ])
                });
                let table = Table::new(
                    rows,
                    [
                        Constraint::Min(16),
                        Constraint::Length(6),
                        Constraint::Min(14),
                        Constraint::Min(14),
                        Constraint::Min(13),
                        Constraint::Length(9),
                        Constraint::Length(10),
                        Constraint::Min(12),
                    ],
                )
                .header(
                    Row::new([
                        "Prefix", "PathId", "Reason", "Detail", "Next Hop", "RPKI", "ASPA",
                        "AS Path",
                    ])
                    .style(header_style),
                )
                .row_highlight_style(highlight)
                .highlight_symbol("> ");
                f.render_stateful_widget(table, body, &mut app.rib_table_state);
            }
            f.render_widget(Paragraph::new(status).style(dim), status_area);
        }
    }

    let explain_hint = if app.rib_view.explains_rows() {
        "Enter Explain"
    } else {
        "Enter n/a (explain from Best/Advertised, or e)"
    };
    let keys = format!(
        "v View | f Family | / Filter | e Explain prefix | Space/PgDn screen | n/p server page | {explain_hint} | r Refresh | Esc Back"
    );
    f.render_widget(Paragraph::new(keys).style(dim), keys_area);

    if let Some(editor) = app.rib_editor.as_ref() {
        draw_prefix_editor(f, editor, app.rib_family, peer, theme);
    }
}

fn rejected_cell(value: &str) -> String {
    if value.is_empty() {
        "-".to_string()
    } else {
        value.to_string()
    }
}

fn draw_prefix_editor(
    f: &mut Frame,
    editor: &PrefixEditor,
    family: RibFamily,
    peer: &str,
    theme: &Theme,
) {
    let area = f.area();
    let width = 64.min(area.width.saturating_sub(2));
    let height = 7;
    if width < 24 || area.height < height {
        return;
    }
    let modal = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };
    f.render_widget(Clear, modal);
    let title = match editor.mode {
        EditorMode::Filter => " Prefix filter ".to_string(),
        EditorMode::Explain => format!(" Explain prefix to {peer} "),
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.accent));
    let inner = block.inner(modal);
    f.render_widget(block, modal);

    let dim = Style::default().fg(theme.text_dim);
    let text = Style::default().fg(theme.text);
    let (before, after) = editor.input.split_at(editor.cursor);
    let input_line = Line::from(vec![
        Span::styled("> ", dim),
        Span::styled(before, text),
        Span::styled("\u{2502}", Style::default().fg(theme.accent)),
        Span::styled(after, text),
    ]);
    let options = match editor.mode {
        EditorMode::Filter => Line::styled(
            format!(
                "[{}] longer prefixes (Tab)",
                if editor.longer { "x" } else { " " }
            ),
            text,
        ),
        EditorMode::Explain => Line::styled(
            "Runs ExplainAdvertisedRoute even when the prefix is absent from Adj-RIB-Out",
            dim,
        ),
    };
    let example = match family {
        RibFamily::Ipv4Unicast => "203.0.113.0/24",
        RibFamily::Ipv6Unicast => "2001:db8::/32",
    };
    let status = match &editor.error {
        Some(error) => Line::styled(error.clone(), Style::default().fg(theme.error)),
        None => Line::styled(
            format!("exact {} prefix, e.g. {example}", family.label()),
            dim,
        ),
    };
    let hint = match editor.mode {
        EditorMode::Filter => "Enter apply (empty clears) | Esc cancel",
        EditorMode::Explain => "Enter explain | Esc cancel",
    };
    f.render_widget(
        Paragraph::new(vec![
            input_line,
            options,
            status,
            Line::from(""),
            Line::styled(hint, dim),
        ]),
        inner,
    );
}

fn draw_advertised_explain(f: &mut Frame, app: &mut App, peer: &str, theme: &Theme) {
    let block = Block::default()
        .title(format!(" Advertised Route Explain | target {peer} "))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));
    let inner = block.inner(f.area());
    f.render_widget(block, f.area());
    let mut lines = match app.explain.as_ref() {
        Some(ExplainState::Loading) | None => vec![Line::from("Loading route explanation...")],
        Some(ExplainState::Error(message)) => vec![Line::styled(
            message.clone(),
            Style::default().fg(theme.error),
        )],
        Some(ExplainState::Ready(explain)) => explain_lines(explain, theme),
    };
    lines.push(Line::from(""));
    lines.push(Line::styled(
        "j/k/Pg/Home/End Scroll | Esc Back",
        Style::default().fg(theme.text_dim),
    ));
    app.set_explain_layout(lines.len(), usize::from(inner.height));
    f.render_widget(
        Paragraph::new(lines).scroll((u16::try_from(app.explain_scroll).unwrap_or(u16::MAX), 0)),
        inner,
    );
}

fn explain_lines(
    explain: &crate::proto::ExplainAdvertisedRouteResponse,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let normalized = crate::commands::rib::explain_to_json(explain);
    let decision = match normalized.decision.as_str() {
        "advertise" => "Advertise",
        "deny" => "Deny",
        "no_best_route" => "No Best Route",
        "unsupported_family" => "Unsupported",
        _ => "Unspecified",
    };
    let mut lines = vec![
        Line::styled(
            format!("Decision: {decision}"),
            Style::default()
                .fg(theme.header_fg)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(format!("Peer: {}", normalized.peer_address)),
        Line::from(format!("Prefix: {}", normalized.prefix)),
    ];
    if !normalized.rd.is_empty() {
        lines.push(Line::from(format!("RD: {}", normalized.rd)));
    }
    if let Some(source) = normalized.source.as_ref() {
        lines.push(Line::from(format!(
            "Source path: {} inbound path ID {}",
            source.peer_address, source.path_id
        )));
    }
    if !normalized.route_peer_address.is_empty() {
        lines.push(Line::from(format!(
            "Route peer: {}",
            normalized.route_peer_address
        )));
    }
    if !normalized.route_type.is_empty() {
        lines.push(Line::from(format!("Route type: {}", normalized.route_type)));
    }
    if !normalized.next_hop.is_empty() {
        lines.push(Line::from(format!("Next hop: {}", normalized.next_hop)));
    }
    if let Some(path_id) = crate::commands::rib::advertised_path_id_line(explain) {
        lines.push(Line::from(path_id));
    }
    if let Some(group) = normalized.update_group_id {
        lines.push(Line::from(format!("Update group: {group}")));
    }
    if !normalized.orr_vantage.is_empty() {
        lines.push(Line::from(format!(
            "ORR vantage: {}",
            normalized.orr_vantage
        )));
    }
    if !normalized.orr_candidates.is_empty() {
        lines.push(Line::styled(
            "ORR candidates (per-vantage best first)",
            Style::default()
                .fg(theme.header_fg)
                .add_modifier(Modifier::BOLD),
        ));
        lines.extend(normalized.orr_candidates.iter().map(|candidate| {
            Line::from(format!(
                "  {} next-hop {} cost={}{}",
                candidate.peer_address,
                candidate.next_hop,
                crate::commands::rib::orr_cost_label(candidate.cost),
                if candidate.selected {
                    " (selected)"
                } else {
                    ""
                }
            ))
        }));
    }
    lines.push(Line::from(format!(
        "Adj-RIB-Out sync: {}",
        if normalized.already_advertised {
            "already advertised"
        } else {
            "not already advertised"
        }
    )));
    if !normalized.reasons.is_empty() {
        lines.push(Line::styled(
            "Reasons",
            Style::default()
                .fg(theme.header_fg)
                .add_modifier(Modifier::BOLD),
        ));
        lines.extend(
            normalized
                .reasons
                .iter()
                .map(|r| Line::from(format!("  {}: {}", r.code, r.message))),
        );
    }
    if !normalized.gates.is_empty() {
        lines.push(Line::styled(
            "Export gates",
            Style::default()
                .fg(theme.header_fg)
                .add_modifier(Modifier::BOLD),
        ));
        lines.extend(normalized.gates.iter().map(|g| {
            Line::from(format!(
                "  {} | {} | {} | {}",
                g.gate, g.verdict, g.code, g.detail
            ))
        }));
    }
    {
        let m = &normalized.modifications;
        let mut mods = Vec::new();
        if let Some(v) = m.set_local_pref {
            mods.push(format!("local-pref={v}"));
        }
        if let Some(v) = m.set_med {
            mods.push(format!("MED={v}"));
        }
        if !m.set_next_hop.is_empty() {
            mods.push(format!("next-hop={}", m.set_next_hop));
        }
        if !m.communities_add.is_empty() {
            mods.push(format!("communities+={}", m.communities_add.join(",")));
        }
        if !m.communities_remove.is_empty() {
            mods.push(format!("communities-={}", m.communities_remove.join(",")));
        }
        if !m.extended_communities_add.is_empty() {
            mods.push(format!(
                "extended-communities+={}",
                m.extended_communities_add
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if !m.extended_communities_remove.is_empty() {
            mods.push(format!(
                "extended-communities-={}",
                m.extended_communities_remove
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if !m.large_communities_add.is_empty() {
            mods.push(format!(
                "large-communities+={}",
                m.large_communities_add.join(",")
            ));
        }
        if !m.large_communities_remove.is_empty() {
            mods.push(format!(
                "large-communities-={}",
                m.large_communities_remove.join(",")
            ));
        }
        if let (Some(asn), Some(count)) = (m.as_path_prepend_asn, m.as_path_prepend_count) {
            mods.push(format!("prepend={asn}x{count}"));
        }
        if !mods.is_empty() {
            lines.push(Line::styled(
                "Modifications",
                Style::default()
                    .fg(theme.header_fg)
                    .add_modifier(Modifier::BOLD),
            ));
            lines.extend(mods.into_iter().map(|m| Line::from(format!("  {m}"))));
        }
    }
    lines
}

fn draw_help_overlay(f: &mut Frame, theme: &Theme) {
    let area = centered_rect(60, 75, f.area());
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
            Span::styled(
                "Show detail / explain selected route",
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  r           ", Style::default().fg(theme.accent)),
            Span::styled(
                "Open route explorer (detail) / refresh (explorer)",
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  v / f       ", Style::default().fg(theme.accent)),
            Span::styled(
                "Cycle Best/Received/Advertised/Rejected / toggle IPv4/IPv6",
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  / and e     ", Style::default().fg(theme.accent)),
            Span::styled(
                "Exact prefix filter / explain a typed prefix",
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Space/PgDn  ", Style::default().fg(theme.accent)),
            Span::styled(
                "Move one screen within the server page",
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  n / p       ", Style::default().fg(theme.accent)),
            Span::styled(
                "Next / previous server page",
                Style::default().fg(theme.text),
            ),
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

fn optional_u32(value: Option<u32>) -> String {
    value.map_or_else(|| "-".to_string(), |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        ExplainDecision, ExportGateVerdict, GlobalState, HealthResponse, NeighborConfig,
        NeighborState,
    };
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

    #[test]
    fn optional_route_attributes_distinguish_absent_from_explicit_zero() {
        assert_eq!(optional_u32(None), "-");
        assert_eq!(optional_u32(Some(0)), "0");
    }

    /// Red proof: restoring the source-only event row or storing the primary
    /// status in the bounded route rows removes these strings from the real
    /// rendered event panel.
    #[test]
    fn event_panel_test_backend_renders_context_lag_and_primary_status() {
        let mut app = App::new();
        app.show_events = true;
        app.on_data(snapshot(Vec::new(), Freshness::Fresh));
        app.on_route_event(crate::tui::data::RouteEventUpdate::StreamStatus(Some(
            "route event stream error: primary unavailable; retrying".into(),
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

        assert!(rendered.contains("route event stream error: primary unavailable; retrying"));
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
                local_address: Some("127.0.0.1".into()),
                hold_time_seconds: Some(30),
                keepalive_interval_seconds: Some(10),
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
        assert!(rendered.contains("r Best RIB"));

        for (label, expected) in [
            ("Configured Hold Time:", "90s"),
            ("Local Address:", "127.0.0.1"),
            ("Negotiated Hold Time:", "30s"),
            ("Keepalive Interval:", "10s"),
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
        for label in [
            "Local Address:",
            "Negotiated Hold Time:",
            "Keepalive Interval:",
            "Negotiated Families:",
        ] {
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

    fn rendered_app(app: &mut App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| draw(frame, app, &Theme::default()))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn best_rib_test_backend_renders_all_states_and_columns_without_tiny_panic() {
        let mut app = App::new();
        app.view = View::RouteExplorer("198.51.100.1".into());
        app.rib_page = Some(RibPageState::Loading);
        assert!(rendered_app(&mut app, 100, 8).contains("Loading routes"));
        app.rib_page = Some(RibPageState::Error("RIB unavailable: down".into()));
        assert!(rendered_app(&mut app, 100, 8).contains("RIB unavailable: down"));
        app.rib_page = Some(RibPageState::Ready(crate::proto::ListRoutesResponse {
            total_count: 0,
            ..Default::default()
        }));
        assert!(rendered_app(&mut app, 100, 8).contains("No best routes"));
        app.rib_page = Some(RibPageState::Ready(crate::proto::ListRoutesResponse {
            routes: vec![crate::proto::Route {
                prefix: "203.0.113.0".into(),
                prefix_length: 24,
                next_hop: "192.0.2.1".into(),
                peer_address: "192.0.2.2".into(),
                as_path: vec![64512, 64496],
                local_pref: 100,
                med_attr: Some(0),
                validation_state: "valid".into(),
                aspa_state: "unknown".into(),
                ..Default::default()
            }],
            total_count: 1,
            ..Default::default()
        }));
        app.rib_table_state.select(Some(0));
        let rendered = rendered_app(&mut app, 150, 8);
        for text in [
            "Routes: Best",
            "global | explain target 198.51.100.1",
            "IPv4 unicast",
            "no filter",
            "203.0.113.0/24",
            "192.0.2.1",
            "64512 64496",
            "LocalPref",
            "MED",
            "RPKI",
            "ASPA",
            "Enter Explain",
        ] {
            assert!(rendered.contains(text), "missing {text}");
        }
        let _ = rendered_app(&mut app, 1, 1);
    }

    #[test]
    fn route_explorer_renders_every_view_status_rejected_rows_and_editor() {
        use crate::tui::app::RIB_RESTART_NOTICE;
        use crate::tui::data::{PrefixFilter, RibView};

        let mut app = App::new();
        app.view = View::RouteExplorer("198.51.100.1".into());
        for (view, expected) in [
            (RibView::Best, "No best routes"),
            (RibView::Received, "No received routes"),
            (RibView::Advertised, "No advertised routes"),
        ] {
            app.rib_view = view;
            app.rib_page = Some(RibPageState::Ready(crate::proto::ListRoutesResponse {
                total_count: 0,
                ..Default::default()
            }));
            let rendered = rendered_app(&mut app, 120, 10);
            assert!(rendered.contains(expected), "missing {expected}");
            assert!(rendered.contains(&format!("Routes: {}", view.label())));
        }
        assert!(rendered_app(&mut app, 120, 10).contains("Enter Explain"));
        app.rib_view = RibView::Received;
        let rendered = rendered_app(&mut app, 120, 10);
        assert!(rendered.contains("peer 198.51.100.1"));
        assert!(rendered.contains("Enter n/a"));

        app.rib_view = RibView::Best;
        app.rib_family = RibFamily::Ipv6Unicast;
        app.rib_filter = Some(PrefixFilter {
            addr: "2001:db8::".parse().unwrap(),
            len: 32,
            longer: true,
        });
        app.rib_notice = Some(RIB_RESTART_NOTICE);
        app.rib_previous_tokens = vec![String::new(), "a".into()];
        app.rib_page = Some(RibPageState::Ready(crate::proto::ListRoutesResponse {
            routes: vec![crate::proto::Route {
                prefix: "2001:db8:1::".into(),
                prefix_length: 48,
                ..Default::default()
            }],
            total_count: 42,
            page_version: Some(crate::proto::RoutePageVersion {
                epoch: 7,
                generation: 77,
            }),
            ..Default::default()
        }));
        app.rib_table_state.select(Some(0));
        let rendered = rendered_app(&mut app, 170, 10);
        for text in [
            "IPv6 unicast",
            "filter 2001:db8::/32 +longer",
            "row 1/1",
            "server page 3",
            "total 42",
            "snapshot 7.77",
            RIB_RESTART_NOTICE,
            "Space/PgDn screen",
            "n/p server page",
            "Enter Explain",
        ] {
            assert!(rendered.contains(text), "missing {text}");
        }
        // 10 rows - 2 borders - status - keys - header = 5 data rows.
        assert_eq!(app.rib_page_height, 5);
        app.rib_page = Some(RibPageState::Ready(crate::proto::ListRoutesResponse {
            total_count: 0,
            ..Default::default()
        }));
        assert!(
            rendered_app(&mut app, 120, 10).contains("No best routes match 2001:db8::/32 +longer")
        );

        app.rib_view = RibView::Rejected;
        let rejected =
            |routes: Vec<crate::proto::RejectedRoute>, retained: usize| RibPageState::Rejected {
                page: crate::proto::ListRejectedRoutesResponse {
                    peer_address: "198.51.100.1".into(),
                    retention_enabled: true,
                    capacity: 1024,
                    routes,
                    evictions_since_reset: Some(2),
                },
                retained,
            };
        app.rib_page = Some(rejected(
            vec![crate::proto::RejectedRoute {
                prefix: "203.0.113.0".into(),
                prefix_length: 24,
                path_id: 3,
                reason: "policy_reject".into(),
                reason_detail: "deny-bogons:term1".into(),
                next_hop: "192.0.2.1".into(),
                as_path: "64512 64496".into(),
                rpki_validation: "invalid".into(),
                ..Default::default()
            }],
            5,
        ));
        app.rib_table_state.select(Some(0));
        let rendered = rendered_app(&mut app, 180, 10);
        for text in [
            "Routes: Rejected",
            "PathId",
            "203.0.113.0/24",
            "policy_reject",
            "deny-bogons:term1",
            "invalid",
            "page 1 of 1",
            "matched 1 of 5 retained (cap 1024)",
            "evictions 2",
            "Enter n/a",
        ] {
            assert!(rendered.contains(text), "missing {text}");
        }
        app.rib_page = Some(rejected(Vec::new(), 3));
        assert!(rendered_app(&mut app, 120, 10).contains("No retained rejected routes match"));
        app.rib_page = Some(rejected(Vec::new(), 0));
        assert!(rendered_app(&mut app, 120, 10).contains("No retained rejected routes"));
        if let Some(RibPageState::Rejected { page, .. }) = app.rib_page.as_mut() {
            page.retention_enabled = false;
            page.evictions_since_reset = None;
        }
        let rendered = rendered_app(&mut app, 120, 10);
        assert!(rendered.contains("retention is disabled"));
        assert!(rendered.contains("evictions unknown"));

        app.rib_editor = Some(PrefixEditor {
            mode: EditorMode::Filter,
            input: "2001:db8::/3".into(),
            cursor: 12,
            longer: true,
            error: None,
        });
        let rendered = rendered_app(&mut app, 120, 12);
        for text in [
            "Prefix filter",
            "2001:db8::/3",
            "[x] longer prefixes (Tab)",
            "exact IPv6 unicast prefix",
            "Enter apply (empty clears)",
        ] {
            assert!(rendered.contains(text), "missing {text}");
        }
        app.rib_editor = Some(PrefixEditor {
            mode: EditorMode::Explain,
            input: String::new(),
            cursor: 0,
            longer: false,
            error: Some("enter a prefix".into()),
        });
        let rendered = rendered_app(&mut app, 120, 12);
        assert!(rendered.contains("Explain prefix to 198.51.100.1"));
        assert!(rendered.contains("enter a prefix"));
        assert!(rendered.contains("Enter explain"));
        let _ = rendered_app(&mut app, 1, 1);
    }

    #[test]
    fn explain_test_backend_renders_verdict_reasons_gates_and_modifications() {
        let mut app = App::new();
        app.view = View::AdvertisedExplain("198.51.100.1".into());
        app.explain = Some(ExplainState::Ready(Box::new(
            crate::proto::ExplainAdvertisedRouteResponse {
                decision: ExplainDecision::Deny as i32,
                peer_address: "198.51.100.1".into(),
                prefix: "203.0.113.0".into(),
                prefix_length: 24,
                next_hop: "192.0.2.1".into(),
                route_peer_address: "192.0.2.2".into(),
                route_type: "external".into(),
                path_id: 42,
                rd: "65000:100".into(),
                source: Some(crate::proto::RouteSourceIdentity {
                    peer_address: "192.0.2.9".into(),
                    path_id: 7,
                }),
                orr_vantage: "10.0.1.1".into(),
                orr_candidates: vec![
                    crate::proto::OrrExplainCandidate {
                        peer_address: "192.0.2.2".into(),
                        next_hop: "192.0.2.1".into(),
                        cost: Some(10),
                        selected: true,
                        ..Default::default()
                    },
                    crate::proto::OrrExplainCandidate {
                        peer_address: "192.0.2.3".into(),
                        next_hop: "192.0.2.254".into(),
                        cost: None,
                        selected: false,
                        ..Default::default()
                    },
                ],
                update_group_id: Some(7),
                already_advertised: true,
                reasons: vec![crate::proto::ExplainReason {
                    code: "policy_denied".into(),
                    message: "term reject-bogon".into(),
                }],
                gates: vec![crate::proto::ExportGateStep {
                    gate: "export_policy".into(),
                    code: "policy_denied".into(),
                    verdict: ExportGateVerdict::Stop as i32,
                    detail: "term reject-bogon".into(),
                }],
                modifications: Some(crate::proto::ExplainModifications {
                    set_local_pref: Some(200),
                    set_med: Some(0),
                    set_next_hop: "192.0.2.9".into(),
                    communities_add: vec![4_259_840_001],
                    extended_communities_add: vec![4_294_967_297, 4_294_967_298],
                    extended_communities_remove: vec![8_589_934_593],
                    large_communities_add: vec!["64512:1:2".into()],
                    as_path_prepend_asn: Some(64512),
                    as_path_prepend_count: Some(2),
                    ..Default::default()
                }),
            },
        )));
        let rendered = rendered_app(&mut app, 160, 40);
        for text in [
            "Decision: Deny",
            "RD: 65000:100",
            "Source path: 192.0.2.9 inbound path ID 7",
            "Route peer: 192.0.2.2",
            "Route type: external",
            "Outbound path ID: 42",
            "Update group: 7",
            "ORR vantage: 10.0.1.1",
            "ORR candidates (per-vantage best first)",
            "192.0.2.2 next-hop 192.0.2.1 cost=10 (selected)",
            "192.0.2.3 next-hop 192.0.2.254 cost=unreachable",
            "already advertised",
            "Reasons",
            "policy_denied",
            "Export gates",
            "export_policy",
            "stop",
            "Modifications",
            "local-pref=200",
            "MED=0",
            "prepend=64512x2",
            "communities+=65000:1",
            "extended-communities+=4294967297,4294967298",
            "extended-communities-=8589934593",
        ] {
            assert!(rendered.contains(text), "missing {text}");
        }
        assert!(!rendered.contains("4259840001"));
        assert!(!rendered.contains("[4294967297"));
        app.explain = Some(ExplainState::Ready(Box::new(
            crate::proto::ExplainAdvertisedRouteResponse {
                decision: ExplainDecision::Advertise as i32,
                ..Default::default()
            },
        )));
        assert!(rendered_app(&mut app, 40, 4).contains("Decision: Advertise"));
        let _ = rendered_app(&mut app, 1, 1);
    }
}
