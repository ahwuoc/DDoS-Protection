use ratatui::widgets::TableState;

use std::net::IpAddr;

#[derive(Clone, PartialEq)]
pub enum View {
    Dashboard,
    BannedList,
    Whitelist,
    Monitor,
    IpDetail(IpAddr),
}

pub struct App {
    pub view: View,
    pub status_msg: String,
    pub table_state: TableState,
    pub last_list_len: usize,
    pub selected_ip: Option<IpAddr>,
}

impl App {
    pub fn new() -> Self {
        Self {
            view: View::Dashboard,
            status_msg: "Ready".to_string(),
            table_state: TableState::default(),
            last_list_len: 0,
            selected_ip: None,
        }
    }

    pub fn go_dashboard(&mut self) {
        self.view = View::Dashboard;
        self.status_msg = "Ready".to_string();
        self.table_state = TableState::default();
        self.last_list_len = 0;
        self.selected_ip = None;
    }

    pub fn next_row(&mut self, len: usize) {
        let i = match self.table_state.selected() {
            Some(i) => if i >= len.saturating_sub(1) { 0 } else { i + 1 },
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    pub fn prev_row(&mut self, len: usize) {
        let i = match self.table_state.selected() {
            Some(i) => if i == 0 { len.saturating_sub(1) } else { i - 1 },
            None => 0,
        };
        self.table_state.select(Some(i));
    }
}
