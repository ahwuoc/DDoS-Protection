use crate::tracker::ConnectionTracker;
use crate::ui::app::App;
use crate::ui::theme::*;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table},
};
use std::net::IpAddr;

const MONITOR_REFRESH_RATE: &str = "1s";
const COL_INDEX: u16 = 3;
const COL_IP: u16 = 15;
const COL_PORT: u16 = 6;
const COL_CONNS: u16 = 5;
const COL_RATE: u16 = 8;
const COL_STRIKES: u16 = 5;
const COL_SCORE: u16 = 5;
const COL_TRAFFIC: u16 = 14;
const COL_STATUS: u16 = 11;
const COL_COUNTRY: u16 = 5;
const COL_ASN: u16 = 15;

pub fn draw_monitor(f: &mut Frame, tracker: &ConnectionTracker, app: &mut App) {
    let tracked = tracker.list_tracked_ips();
    app.last_list_len = tracked.len();
    let (banned, white, active) = tracker.get_stats();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(3), // Summary
            Constraint::Min(5),    // Table
            Constraint::Length(3), // Footer
        ])
        .split(f.size());

    let now = chrono::Local::now().format("%H:%M:%S");
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " REALTIME MONITOR ",
            label_style(Color::Green).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  [Auto-refresh {}]  {}", MONITOR_REFRESH_RATE, now),
            label_style(Color::DarkGray),
        ),
    ]))
    .alignment(Alignment::Center)
    .block(border_block(" Monitor ", Color::Green));
    f.render_widget(header, chunks[0]);

    let summary = Paragraph::new(Line::from(vec![
        Span::styled(
            format!("  Tracking: {} IPs", tracked.len()),
            label_style(Color::White),
        ),
        Span::styled("  |  Active: ", label_style(Color::DarkGray)),
        Span::styled(active.to_string(), label_style(Color::Yellow)),
        Span::styled("  |  Banned: ", label_style(Color::DarkGray)),
        Span::styled(banned.to_string(), label_style(Color::Red)),
        Span::styled("  |  Whitelist: ", label_style(Color::DarkGray)),
        Span::styled(white.to_string(), label_style(Color::Green)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(summary, chunks[1]);

    let header_cells = [
        "#",
        "IP Address",
        "Port",
        "Conns",
        "Req/m",
        "Strk",
        "Scor",
        "Traffic (↑/↓)",
        "Status",
        "Ctry",
        "ASN",
    ]
    .iter()
    .map(|h| Cell::from(*h).style(key_style()));

    let rows: Vec<Row> = tracked
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let status_color = match t.status.as_str() {
                "WHITELISTED" => Color::Green,
                "BANNED" => Color::Red,
                "TEMP_BLOCK" => Color::Magenta,
                _ => Color::White,
            };
            Row::new(vec![
                Cell::from(format!("{}", i + 1)),
                Cell::from(t.ip.to_string()).style(value_style()),
                Cell::from(if t.last_port > 0 { t.last_port.to_string() } else { "---".to_string() }).style(label_style(Color::Rgb(200, 200, 200))),
                Cell::from(t.active_connections.to_string()).style(label_style(Color::Yellow)),
                Cell::from(t.connects_per_min.to_string()).style(label_style(Color::Cyan)),
                Cell::from(t.strikes.to_string()).style(label_style(if t.strikes > 0 {
                    Color::Red
                } else {
                    Color::DarkGray
                })),
                Cell::from(format!("{:.1}", t.behavior_score)).style(label_style(
                    if t.behavior_score > 5.0 {
                        Color::Red
                    } else if t.behavior_score > 0.0 {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    },
                )),
                Cell::from(format!(
                    "{}/{}",
                    format_bytes(t.total_bytes_sent),
                    format_bytes(t.total_bytes_recv)
                ))
                .style(label_style(Color::Rgb(150, 150, 150))),
                Cell::from(t.status.clone()).style(label_style(status_color)),
                Cell::from(t.country.clone()).style(label_style(Color::Yellow)),
                Cell::from(t.asn_org.clone()).style(label_style(Color::DarkGray)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(COL_INDEX),
            Constraint::Length(COL_IP),
            Constraint::Length(COL_PORT),
            Constraint::Length(COL_CONNS),
            Constraint::Length(COL_RATE),
            Constraint::Length(COL_STRIKES),
            Constraint::Length(COL_SCORE),
            Constraint::Length(COL_TRAFFIC),
            Constraint::Length(COL_STATUS),
            Constraint::Length(COL_COUNTRY),
            Constraint::Length(COL_ASN),
        ],
    )
    .header(
        Row::new(header_cells)
            .height(1)
            .style(Style::default().bg(Color::DarkGray)),
    )
    .block(border_block(" Active Connections ", Color::Green))
    .highlight_style(Style::default().bg(Color::Rgb(30, 30, 30)))
    .highlight_symbol(">> ");

    f.render_stateful_widget(table, chunks[2], &mut app.table_state);

    let footer = Paragraph::new(Line::from(Span::styled(
        " [Up/Down] Select  [Enter] Detailed Info  [U] Unban IP  [Q] Back",
        label_style(Color::DarkGray),
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, chunks[3]);
}

pub fn draw_ip_detail(f: &mut Frame, tracker: &ConnectionTracker, _app: &mut App, ip: IpAddr) {
    let area = centered_rect(60, 60, f.size());
    f.render_widget(Clear, area);

    let stats = tracker.get_ip_stats(ip).unwrap_or_default();

    let title = format!(" Detailed Stats: {} ", ip);
    let block = border_block(&title, Color::Cyan);
    let text = vec![
        Line::from(vec![
            Span::styled(" Status:      ", key_style()),
            Span::styled(format!("{:?}", stats.status), value_style()),
        ]),
        Line::from(vec![
            Span::styled(" Geo Location: ", key_style()),
            Span::styled(
                format!("{} | {}", stats.country, stats.asn_org),
                value_style(),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Active Conns: ", key_style()),
            Span::styled(stats.active_connections.to_string(), value_style()),
        ]),
        Line::from(vec![
            Span::styled(" Rate Limit:   ", key_style()),
            Span::styled(
                format!("{} req within window", stats.connects_in_window),
                value_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Last Minute:  ", key_style()),
            Span::styled(
                format!("{} total connections", stats.connects_in_minute),
                value_style(),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Total Sent:   ", key_style()),
            Span::styled(format_bytes(stats.total_bytes_sent), value_style()),
        ]),
        Line::from(vec![
            Span::styled(" Total Recv:   ", key_style()),
            Span::styled(format_bytes(stats.total_bytes_recv), value_style()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Behavior Score: ", key_style()),
            Span::styled(
                format!("{:.2}", stats.behavior_score),
                if stats.behavior_score > 5.0 {
                    label_style(Color::Red)
                } else {
                    value_style()
                },
            ),
        ]),
        Line::from(vec![
            Span::styled(" Current Strikes:", key_style()),
            Span::styled(
                stats.strikes.to_string(),
                if stats.strikes > 0 {
                    label_style(Color::Red)
                } else {
                    value_style()
                },
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " Press [Q] or [Esc] to close ",
            label_style(Color::DarkGray).add_modifier(Modifier::ITALIC),
        )),
    ];

    let paragraph = Paragraph::new(text).block(block).alignment(Alignment::Left);
    f.render_widget(paragraph, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    }
}
