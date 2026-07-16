use std::collections::VecDeque;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::{ListState, TableState};

use crate::kb::kb::{Alert, ContainmentLevel, KbEvent, ProcessState, SystemStats, Zone};

pub const MAX_ALERTS: usize = 300;
pub const MAX_EVENTS: usize = 200;
pub const MAX_CONSOLE_LINES: usize = 500;
pub const EPS_HISTORY_LEN: usize = 60;
pub const STATUS_MSG_TTL_MS: u128 = 4000;

/// Messages produced by background tasks (gRPC streams, demo generator) and
/// consumed by the main loop to update `App` state.
#[derive(Debug, Clone)]
pub enum AppEvent {
    Connected,
    ConnectionFailed(String),
    ProcessSnapshot(Vec<ProcessState>),
    Alert(Alert),
    KbEvent(KbEvent),
    Stats(SystemStats),
    ContainmentResult {
        pid: u32,
        success: bool,
        message: String,
    },
    QueryResult(Vec<String>),
}

/// Side effects requested by a keypress that require an async RPC; the main
/// loop dispatches these against the live client (or reports offline/demo).
#[derive(Debug, Clone)]
pub enum Action {
    None,
    Quit,
    SubmitContainment {
        pid: u32,
        level: ContainmentLevel,
        reason: String,
    },
    RunQuery(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Processes,
    Alerts,
    Activity,
    Query,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Processes, Tab::Alerts, Tab::Activity, Tab::Query];

    pub fn title(&self) -> &'static str {
        match self {
            Tab::Processes => "Processes",
            Tab::Alerts => "Alerts",
            Tab::Activity => "Agent Activity",
            Tab::Query => "Query Console",
        }
    }

    fn next(self) -> Tab {
        let idx = Tab::ALL.iter().position(|t| *t == self).unwrap();
        Tab::ALL[(idx + 1) % Tab::ALL.len()]
    }

    fn prev(self) -> Tab {
        let idx = Tab::ALL.iter().position(|t| *t == self).unwrap();
        Tab::ALL[(idx + Tab::ALL.len() - 1) % Tab::ALL.len()]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnState {
    Connecting,
    Live,
    Demo,
    Offline(String),
}

#[derive(Debug, Clone)]
pub struct PendingContainment {
    pub pid: u32,
    pub comm: String,
    pub level: Option<ContainmentLevel>,
}

pub struct App {
    pub should_quit: bool,
    pub conn: ConnState,
    pub tab: Tab,

    pub processes: Vec<ProcessState>,
    pub table_state: TableState,
    pub filter: String,
    pub filter_active: bool,

    pub alerts: VecDeque<Alert>,
    pub alert_list_state: ListState,
    pub alert_expanded: bool,

    pub events: VecDeque<KbEvent>,
    pub activity_list_state: ListState,

    pub stats: Option<SystemStats>,
    pub eps_history: VecDeque<f64>,

    pub query_input: String,
    pub query_console: Vec<String>,
    pub query_history: Vec<String>,
    pub query_history_idx: Option<usize>,

    pub pending_containment: Option<PendingContainment>,
    pub show_help: bool,
    pub status_msg: Option<(String, Instant)>,
}

impl App {
    pub fn new() -> Self {
        Self {
            should_quit: false,
            conn: ConnState::Connecting,
            tab: Tab::Processes,
            processes: Vec::new(),
            table_state: TableState::default(),
            filter: String::new(),
            filter_active: false,
            alerts: VecDeque::new(),
            alert_list_state: ListState::default(),
            alert_expanded: false,
            events: VecDeque::new(),
            activity_list_state: ListState::default(),
            stats: None,
            eps_history: VecDeque::new(),
            query_input: String::new(),
            query_console: vec![
                "kb-tui query console — type 'help' for commands.".to_string(),
            ],
            query_history: Vec::new(),
            query_history_idx: None,
            pending_containment: None,
            show_help: false,
            status_msg: None,
        }
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_msg = Some((msg.into(), Instant::now()));
    }

    pub fn tick(&mut self) {
        if let Some((_, at)) = &self.status_msg {
            if at.elapsed().as_millis() > STATUS_MSG_TTL_MS {
                self.status_msg = None;
            }
        }
    }

    pub fn apply_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Connected => {
                self.conn = ConnState::Live;
                self.set_status("connected to kbd over /run/kb/kba.sock");
            }
            AppEvent::ConnectionFailed(reason) => {
                self.conn = ConnState::Offline(reason);
            }
            AppEvent::ProcessSnapshot(mut procs) => {
                if matches!(self.conn, ConnState::Offline(_)) {
                    self.conn = ConnState::Demo;
                }
                procs.sort_by(|a, b| b.zone.cmp(&a.zone).then(b.score.total_cmp(&a.score)));
                let selected_pid = self
                    .table_state
                    .selected()
                    .and_then(|i| self.visible_indices(&procs).get(i).copied())
                    .and_then(|i| procs.get(i))
                    .map(|p| p.pid);
                self.processes = procs;
                if let Some(pid) = selected_pid {
                    let vis = self.visible_indices(&self.processes);
                    if let Some(pos) = vis.iter().position(|&i| self.processes[i].pid == pid) {
                        self.table_state.select(Some(pos));
                    }
                }
                if self.table_state.selected().is_none() && !self.processes.is_empty() {
                    self.table_state.select(Some(0));
                }
            }
            AppEvent::Alert(alert) => {
                if matches!(self.conn, ConnState::Offline(_)) {
                    self.conn = ConnState::Demo;
                }
                self.alerts.push_front(alert);
                while self.alerts.len() > MAX_ALERTS {
                    self.alerts.pop_back();
                }
            }
            AppEvent::KbEvent(ev) => {
                if matches!(self.conn, ConnState::Offline(_)) {
                    self.conn = ConnState::Demo;
                }
                self.events.push_front(ev);
                while self.events.len() > MAX_EVENTS {
                    self.events.pop_back();
                }
            }
            AppEvent::Stats(stats) => {
                self.eps_history.push_back(stats.events_per_second);
                while self.eps_history.len() > EPS_HISTORY_LEN {
                    self.eps_history.pop_front();
                }
                self.stats = Some(stats);
            }
            AppEvent::ContainmentResult {
                pid,
                success,
                message,
            } => {
                if success {
                    self.set_status(format!("pid {pid}: {message}"));
                } else {
                    self.set_status(format!("pid {pid} containment failed: {message}"));
                }
            }
            AppEvent::QueryResult(lines) => {
                if lines.first().map(String::as_str) == Some("__CLEAR__") {
                    self.query_console.clear();
                } else {
                    self.query_console.extend(lines);
                }
                while self.query_console.len() > MAX_CONSOLE_LINES {
                    self.query_console.remove(0);
                }
            }
        }
    }

    /// Indices into `procs` that pass the active filter, in display order.
    pub fn visible_indices(&self, procs: &[ProcessState]) -> Vec<usize> {
        let needle = self.filter.to_lowercase();
        procs
            .iter()
            .enumerate()
            .filter(|(_, p)| needle.is_empty() || p.comm.to_lowercase().contains(&needle))
            .map(|(i, _)| i)
            .collect()
    }

    pub fn visible_processes(&self) -> Vec<&ProcessState> {
        self.visible_indices(&self.processes)
            .into_iter()
            .map(|i| &self.processes[i])
            .collect()
    }

    pub fn selected_process(&self) -> Option<&ProcessState> {
        let vis = self.visible_processes();
        self.table_state.selected().and_then(|i| vis.get(i).copied())
    }

    fn text_input_active(&self) -> bool {
        self.filter_active || self.tab == Tab::Query
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Action::Quit;
        }

        if self.show_help {
            if matches!(key.code, KeyCode::Char('?') | KeyCode::Esc) {
                self.show_help = false;
            }
            return Action::None;
        }

        if let Some(pc) = self.pending_containment.clone() {
            return self.handle_containment_modal_key(pc, key);
        }

        // Tab cycling is always available.
        match key.code {
            KeyCode::Tab => {
                self.tab = self.tab.next();
                return Action::None;
            }
            KeyCode::BackTab => {
                self.tab = self.tab.prev();
                return Action::None;
            }
            KeyCode::Char('?') if !self.text_input_active() => {
                self.show_help = true;
                return Action::None;
            }
            _ => {}
        }

        match self.tab {
            Tab::Processes => self.handle_processes_key(key),
            Tab::Alerts => self.handle_alerts_key(key),
            Tab::Activity => self.handle_activity_key(key),
            Tab::Query => self.handle_query_key(key),
        }
    }

    fn handle_containment_modal_key(
        &mut self,
        pc: PendingContainment,
        key: KeyEvent,
    ) -> Action {
        match pc.level {
            None => match key.code {
                KeyCode::Char('0') => {
                    self.pending_containment.as_mut().unwrap().level = Some(ContainmentLevel::None);
                }
                KeyCode::Char('1') => {
                    self.pending_containment.as_mut().unwrap().level = Some(ContainmentLevel::Cgroup);
                }
                KeyCode::Char('2') => {
                    self.pending_containment.as_mut().unwrap().level = Some(ContainmentLevel::Seccomp);
                }
                KeyCode::Char('3') => {
                    self.pending_containment.as_mut().unwrap().level =
                        Some(ContainmentLevel::Namespace);
                }
                KeyCode::Char('4') => {
                    self.pending_containment.as_mut().unwrap().level =
                        Some(ContainmentLevel::Terminate);
                }
                KeyCode::Esc => self.pending_containment = None,
                _ => {}
            },
            Some(level) => match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    self.pending_containment = None;
                    return Action::SubmitContainment {
                        pid: pc.pid,
                        level,
                        reason: "operator action via kb-tui".to_string(),
                    };
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.pending_containment.as_mut().unwrap().level = None;
                }
                _ => {}
            },
        }
        Action::None
    }

    fn handle_processes_key(&mut self, key: KeyEvent) -> Action {
        if self.filter_active {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.filter_active = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) => self.filter.push(c),
                _ => {}
            }
            self.table_state.select(Some(0));
            return Action::None;
        }

        match key.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::Char('/') => self.filter_active = true,
            KeyCode::Esc if !self.filter.is_empty() => {
                self.filter.clear();
                self.table_state.select(Some(0));
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Char('c') => {
                if let Some(p) = self.selected_process() {
                    self.pending_containment = Some(PendingContainment {
                        pid: p.pid,
                        comm: p.comm.clone(),
                        level: None,
                    });
                } else {
                    self.set_status("no process selected");
                }
            }
            _ => {}
        }
        Action::None
    }

    fn move_selection(&mut self, delta: i32) {
        let len = self.visible_processes().len();
        if len == 0 {
            self.table_state.select(None);
            return;
        }
        let cur = self.table_state.selected().unwrap_or(0) as i32;
        let next = (cur + delta).rem_euclid(len as i32) as usize;
        self.table_state.select(Some(next));
    }

    fn handle_alerts_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::Up | KeyCode::Char('k') => list_move(&mut self.alert_list_state, self.alerts.len(), -1),
            KeyCode::Down | KeyCode::Char('j') => list_move(&mut self.alert_list_state, self.alerts.len(), 1),
            KeyCode::Enter => self.alert_expanded = !self.alert_expanded,
            _ => {}
        }
        Action::None
    }

    fn handle_activity_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::Up | KeyCode::Char('k') => {
                list_move(&mut self.activity_list_state, self.events.len(), -1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                list_move(&mut self.activity_list_state, self.events.len(), 1)
            }
            _ => {}
        }
        Action::None
    }

    fn handle_query_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Enter => {
                let cmd = self.query_input.trim().to_string();
                if cmd.is_empty() {
                    return Action::None;
                }
                self.query_console.push(format!("> {cmd}"));
                self.query_history.push(cmd.clone());
                self.query_history_idx = None;
                self.query_input.clear();
                return Action::RunQuery(cmd);
            }
            KeyCode::Backspace => {
                self.query_input.pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.query_input.clear();
            }
            KeyCode::Char(c) => self.query_input.push(c),
            KeyCode::Up => self.query_history_step(-1),
            KeyCode::Down => self.query_history_step(1),
            _ => {}
        }
        Action::None
    }

    fn query_history_step(&mut self, delta: i32) {
        if self.query_history.is_empty() {
            return;
        }
        let len = self.query_history.len() as i32;
        let cur = self.query_history_idx.map(|i| i as i32).unwrap_or(len);
        let next = (cur + delta).clamp(0, len);
        self.query_history_idx = if next == len { None } else { Some(next as usize) };
        self.query_input = self
            .query_history_idx
            .and_then(|i| self.query_history.get(i))
            .cloned()
            .unwrap_or_default();
    }
}

fn list_move(state: &mut ListState, len: usize, delta: i32) {
    if len == 0 {
        state.select(None);
        return;
    }
    let cur = state.selected().unwrap_or(0) as i32;
    let next = (cur + delta).rem_euclid(len as i32) as usize;
    state.select(Some(next));
}

pub fn zone_label(zone: i32) -> &'static str {
    match Zone::try_from(zone).unwrap_or(Zone::Safe) {
        Zone::Safe => "SAFE",
        Zone::Suspicious => "SUSPICIOUS",
        Zone::Borderlands => "BORDERLANDS",
    }
}

pub fn containment_label(level: i32) -> &'static str {
    match ContainmentLevel::try_from(level).unwrap_or(ContainmentLevel::None) {
        ContainmentLevel::None => "NONE",
        ContainmentLevel::Cgroup => "CGROUP",
        ContainmentLevel::Seccomp => "SECCOMP",
        ContainmentLevel::Namespace => "NAMESPACE",
        ContainmentLevel::Terminate => "TERMINATE",
    }
}
