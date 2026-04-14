use crate::tracker::ConnectionTracker;
use anyhow::Result;
use crossterm::{
    ExecutableCommand,
    event::{self, Event, KeyCode, KeyEvent},
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use inquire::Select;
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

// ── View State ──────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum View {
    Dashboard,
    BannedList,
    Whitelist,
    Monitor,
}

struct App {
    view: View,
    status_msg: String,
    table_state: TableState,
}

impl App {
    fn new() -> Self {
        Self {
            view: View::Dashboard,
            status_msg: "Ready".to_string(),
            table_state: TableState::default(),
        }
    }

    fn go_dashboard(&mut self) {
        self.view = View::Dashboard;
        self.status_msg = "Ready".to_string();
        self.table_state = TableState::default();
    }

    fn next_row(&mut self, len: usize) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= len.saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn prev_row(&mut self, len: usize) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    len.saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }
}

// ── Style helpers ───────────────────────────────────────

fn key_style() -> Style {
    Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

fn label_style(color: Color) -> Style {
    Style::default().fg(color)
}

fn value_style() -> Style {
    Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD)
}

fn border_block(title: &str, color: Color) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .title(title)
        .title_alignment(Alignment::Center)
}

// ── Main entry ──────────────────────────────────────────

pub fn run_menu(tracker: Arc<ConnectionTracker>) -> Result<()> {
    terminal::enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let mut app = App::new();

    loop {
        terminal.draw(|f| match app.view {
            View::Dashboard => draw_dashboard(f, &tracker, &app),
            View::BannedList => draw_ip_table(f, &tracker, &mut app, true),
            View::Whitelist => draw_ip_table(f, &tracker, &mut app, false),
            View::Monitor => draw_monitor(f, &tracker, &mut app),
        })?;

        // Monitor & Lists: handle scrolling + back
        let is_scrollable = matches!(app.view, View::Monitor | View::BannedList | View::Whitelist);

        if is_scrollable {
            let list_len = match app.view {
                View::Monitor => tracker.list_tracked_ips().len(),
                View::BannedList => tracker.list_banned_ips().len(),
                View::Whitelist => tracker.list_whitelisted_ips().len(),
                _ => 0,
            };

            if event::poll(Duration::from_millis(if app.view == View::Monitor {
                1000
            } else {
                100
            }))? {
                if let Ok(Event::Key(KeyEvent { code, .. })) = event::read() {
                    match code {
                        KeyCode::Char('q' | 'Q') | KeyCode::Esc => app.go_dashboard(),
                        KeyCode::Down | KeyCode::Char('j') => app.next_row(list_len),
                        KeyCode::Up | KeyCode::Char('k') => app.prev_row(list_len),
                        _ => {}
                    }
                }
            }
            continue;
        }

        if let Ok(Event::Key(KeyEvent { code, .. })) = event::read() {
            match app.view {
                View::Dashboard => match code {
                    KeyCode::Char('b' | 'B') => {
                        app.view = View::BannedList;
                        app.table_state.select(Some(0));
                    }
                    KeyCode::Char('u' | 'U') => {
                        drop_tui(&mut terminal)?;
                        do_unban(&tracker, &mut app);
                        restore_tui(&mut terminal)?;
                    }
                    KeyCode::Char('w' | 'W') => {
                        app.view = View::Whitelist;
                        app.table_state.select(Some(0));
                    }
                    KeyCode::Char('m' | 'M') => {
                        app.view = View::Monitor;
                        app.table_state.select(Some(0));
                        app.status_msg = "Monitor active".to_string();
                    }
                    KeyCode::Char('r' | 'R') => app.status_msg = "Refreshed".to_string(),
                    KeyCode::Char('q' | 'Q') | KeyCode::Esc => break,
                    _ => {}
                },
                _ => app.go_dashboard(),
            }
        }
    }

    terminal::disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

// ── TUI suspend/restore for inquire ─────────────────────

fn drop_tui(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    terminal.clear()?;
    terminal::disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

fn restore_tui(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    io::stdout().execute(EnterAlternateScreen)?;
    terminal::enable_raw_mode()?;
    terminal.clear()?;
    Ok(())
}

// ── Dashboard View ──────────────────────────────────────

fn draw_dashboard(f: &mut Frame, tracker: &ConnectionTracker, app: &App) {
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

// ── Monitor View ────────────────────────────────────────

fn draw_monitor(f: &mut Frame, tracker: &ConnectionTracker, app: &mut App) {
    let tracked = tracker.list_tracked_ips();
    let (banned, white, active) = tracker.get_stats();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(f.size());

    let now = chrono::Local::now().format("%H:%M:%S");
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " REALTIME MONITOR ",
            label_style(Color::Green).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  [Auto-refresh 1s]  {now}"),
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
        "Conns",
        "Req/min",
        "Strikes",
        "Status",
        "Country",
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
                Cell::from(t.active_connections.to_string()).style(label_style(Color::Yellow)),
                Cell::from(t.connects_per_min.to_string()).style(label_style(Color::Cyan)),
                Cell::from(t.strikes.to_string()).style(label_style(if t.strikes > 0 {
                    Color::Red
                } else {
                    Color::DarkGray
                })),
                Cell::from(t.status.clone()).style(label_style(status_color)),
                Cell::from(t.country.clone()).style(label_style(Color::Yellow)),
                Cell::from(t.asn_org.clone()).style(label_style(Color::DarkGray)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(18),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Min(20),
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
        " [Up/Down] Scroll  [Q] Back",
        label_style(Color::DarkGray),
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, chunks[3]);
}

// ── IP Table View (Banned / Whitelist) ──────────────────

fn draw_ip_table(f: &mut Frame, tracker: &ConnectionTracker, app: &mut App, is_banned: bool) {
    let (ips, title, color) = if is_banned {
        (tracker.list_banned_ips(), " Banned IPs ", Color::Red)
    } else {
        (
            tracker.list_whitelisted_ips(),
            " Whitelisted IPs ",
            Color::Green,
        )
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(f.size());

    let header_text = format!("{} ({} IPs)", title.trim(), ips.len());
    let header = Paragraph::new(Line::from(Span::styled(
        header_text,
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )))
    .alignment(Alignment::Center)
    .block(border_block(title, color));
    f.render_widget(header, chunks[0]);

    let header_row = Row::new(
        ["#", "IP Address", "Country", "ASN Organization"]
            .iter()
            .map(|h| Cell::from(*h).style(key_style())),
    )
    .height(1)
    .style(Style::default().bg(Color::DarkGray));

    let rows: Vec<Row> = ips
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            let info = tracker.get_ip_info(*ip);
            Row::new(vec![
                Cell::from(format!("{}", i + 1)),
                Cell::from(ip.to_string()).style(value_style()),
                Cell::from(info.country).style(label_style(Color::Yellow)),
                Cell::from(info.asn_org).style(label_style(Color::Cyan)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(20),
            Constraint::Length(10),
            Constraint::Min(30),
        ],
    )
    .header(header_row)
    .block(border_block(title, color))
    .highlight_style(Style::default().bg(Color::Rgb(30, 30, 30)))
    .highlight_symbol(">> ");

    f.render_stateful_widget(table, chunks[1], &mut app.table_state);

    let footer = Paragraph::new(Line::from(Span::styled(
        " [Up/Down] Scroll  [Q] Back",
        label_style(Color::DarkGray),
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, chunks[2]);
}

// ── Unban Flow ──────────────────────────────────────────

fn do_unban(tracker: &ConnectionTracker, app: &mut App) {
    let banned = tracker.list_banned_ips();
    if banned.is_empty() {
        println!("\n  No IPs are currently banned.\n");
        wait_enter();
        app.status_msg = "No IPs to unban".to_string();
        return;
    }

    let choices: Vec<String> = banned
        .iter()
        .map(|ip| {
            let info = tracker.get_ip_info(*ip);
            format!("{:<18} [{}] {}", ip, info.country, info.asn_org)
        })
        .collect();

    match Select::new("Select IP to unban:", choices).prompt() {
        Ok(selected) => {
            let ip_str = selected.split_whitespace().next().unwrap_or("");
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                if let Err(e) = tracker.unban(ip) {
                    println!("\n  Error: {}\n", e);
                    app.status_msg = format!("Error: {}", e);
                } else {
                    println!("\n  Unbanned successfully: {}\n", ip);
                    app.status_msg = format!("Unbanned: {}", ip);
                }
            }
        }
        Err(_) => app.status_msg = "Cancelled".to_string(),
    }
    wait_enter();
}

fn wait_enter() {
    println!(" Press Enter to continue...");
    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf);
}
