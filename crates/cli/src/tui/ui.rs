use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};

use crate::output::{format_duration, format_family, format_state};
use crate::tui::app::{App, SortColumn, View};
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

    let content = Paragraph::new(Line::from(vec![Span::raw(" Status: "), status])).block(block);
    f.render_widget(content, area);
}

fn draw_peer_table(f: &mut Frame, app: &mut App, area: Rect, theme: &Theme) {
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
    });

    let header = Row::new(header_cells).height(1);

    let rows = app.neighbors.iter().map(|n| {
        let cfg = n.config.as_ref();
        let addr = cfg.map(|c| c.address.as_str()).unwrap_or("");
        let asn = cfg.map(|c| c.remote_asn.to_string()).unwrap_or_default();
        let state_label = format_state(n.state);
        let state_color = theme.state_color(n.state);
        let uptime = format_duration(n.uptime_seconds);
        let rx = format_number(n.prefixes_received);
        let tx = format_number(n.prefixes_sent);
        let rate = app.peer_update_rate(addr);
        let rate_str = if rate < 0.05 {
            "0.0".to_string()
        } else {
            format!("{rate:.1}")
        };
        let flaps = n.flap_count.to_string();
        let desc = cfg.map(|c| c.description.as_str()).unwrap_or("");

        Row::new(vec![
            Cell::from(addr.to_string()),
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
    let elapsed = app.last_update.elapsed().as_secs();
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
    let right = format!("Last update: {ago} ");

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
    let Some(neighbor) = app.neighbors.iter().find(|neighbor| {
        neighbor
            .config
            .as_ref()
            .map(|config| config.address.as_str())
            == Some(address)
    }) else {
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

    let state_label = format_state(neighbor.state);
    let state_color = theme.state_color(neighbor.state);
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
            "  rustbgpctl top — Live TUI Dashboard",
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

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(12345), "12,345");
        assert_eq!(format_number(1234567), "1,234,567");
    }
}
