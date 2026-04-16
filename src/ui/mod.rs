use crate::tracker::ConnectionTracker;
use anyhow::Result;
use crossterm::{
    ExecutableCommand,
    event::{self, Event, KeyCode, KeyEvent},
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io;
use std::sync::Arc;
use std::time::Duration;

mod actions;
mod app;
mod dashboard;
mod monitor;
mod tables;
mod theme;

pub use app::{App, View};

pub fn run_menu(tracker: Arc<ConnectionTracker>) -> Result<()> {
    terminal::enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let mut app = App::new();

    loop {
        terminal.draw(|f| match app.view.clone() {
            View::Dashboard => dashboard::draw_dashboard(f, &tracker, &app),
            View::BannedList => tables::draw_ip_table(f, &tracker, &mut app, true),
            View::Whitelist => tables::draw_ip_table(f, &tracker, &mut app, false),
            View::Monitor => monitor::draw_monitor(f, &tracker, &mut app),
            View::IpDetail(ip) => monitor::draw_ip_detail(f, &tracker, &mut app, ip),
        })?;

        let is_scrollable = matches!(app.view, View::Monitor | View::BannedList | View::Whitelist);

        if is_scrollable {
            let list_len = app.last_list_len;
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
                        KeyCode::Enter => {
                            if app.view == View::Monitor {
                                let tracked = tracker.list_tracked_ips();
                                if let Some(idx) = app.table_state.selected() {
                                    if let Some(snapshot) = tracked.get(idx) {
                                        app.view = View::IpDetail(snapshot.ip);
                                    }
                                }
                            }
                        }
                        KeyCode::Char('u' | 'U') => {
                            if app.view == View::Monitor {
                                let tracked = tracker.list_tracked_ips();
                                if let Some(idx) = app.table_state.selected() {
                                    if let Some(snapshot) = tracked.get(idx) {
                                        let _ = tracker.unban(snapshot.ip);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            continue;
        }

        if let Ok(Event::Key(KeyEvent { code, .. })) = event::read() {
            match &app.view {
                View::IpDetail(_) => match code {
                    KeyCode::Char('q' | 'Q') | KeyCode::Esc => {
                        app.view = View::Monitor;
                    }
                    _ => {}
                },
                View::Dashboard => match code {
                    KeyCode::Char('b' | 'B') => {
                        app.view = View::BannedList;
                        app.table_state.select(Some(0));
                    }
                    KeyCode::Char('u' | 'U') => {
                        drop_tui(&mut terminal)?;
                        actions::do_unban(&tracker, &mut app);
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
