use crate::engine::ConnectionTracker;
use crate::ui::app::App;
use crate::ui::theme::*;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

pub fn draw_ip_table(f: &mut Frame, tracker: &ConnectionTracker, app: &mut App, is_banned: bool) {
    let (ips, title, color) = if is_banned {
        (tracker.list_banned_ips(), " Banned IPs ", Color::Red)
    } else {
        (tracker.list_whitelisted_ips(), " Whitelisted IPs ", Color::Green)
    };
    app.last_list_len = ips.len();

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
