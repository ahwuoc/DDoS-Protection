use crate::tracker::ConnectionTracker;
use crate::ui::app::App;
use crate::ui::theme::*;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

pub fn draw_dashboard(f: &mut Frame, tracker: &ConnectionTracker, app: &App) {
    let (banned, white, active) = tracker.get_stats();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(14),
            Constraint::Length(3),
        ])
        .split(f.size());

    let title = Paragraph::new(Line::from(Span::styled(
        " PROXY FORWARD — CONTROL PANEL ",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )))
    .alignment(Alignment::Center)
    .block(border_block(" DDoS Protection ", Color::Cyan));
    f.render_widget(title, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let stats_lines = vec![
        Line::from(""),
        stat_line("  Banned IPs       ", banned, Color::Red),
        Line::from(""),
        stat_line("  Whitelisted IPs  ", white, Color::Green),
        Line::from(""),
        stat_line("  Active Conns     ", active, Color::Yellow),
        Line::from(""),
    ];
    let stats = Paragraph::new(stats_lines).block(border_block(" Live Stats ", Color::Blue));
    f.render_widget(stats, body[0]);

    let hotkey_lines = vec![
        Line::from(""),
        hotkey_line("[B]", "  Banned IPs list"),
        Line::from(""),
        hotkey_line("[U]", "  Unban an IP"),
        Line::from(""),
        hotkey_line("[W]", "  Whitelist view"),
        Line::from(""),
        hotkey_line("[M]", "  Monitor realtime"),
        Line::from(""),
        hotkey_line("[R]", "  Refresh stats"),
        Line::from(""),
        hotkey_line("[Q]", "  Quit panel"),
        Line::from(""),
    ];
    let hotkeys = Paragraph::new(hotkey_lines).block(border_block(" Hotkeys ", Color::Blue));
    f.render_widget(hotkeys, body[1]);

    let status = Paragraph::new(Line::from(vec![
        Span::styled(" Status: ", label_style(Color::DarkGray)),
        Span::styled(&app.status_msg, label_style(Color::Green)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(status, chunks[2]);
}

fn stat_line(label: &str, value: usize, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}:  "), label_style(color)),
        Span::styled(value.to_string(), value_style()),
    ])
}

fn hotkey_line(key: &str, desc: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("   {key}"), key_style()),
        Span::raw(desc.to_string()),
    ])
}
