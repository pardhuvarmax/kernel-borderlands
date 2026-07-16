use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Sparkline, Table, Tabs, Wrap,
};
use ratatui::Frame;

use crate::app::{containment_label, zone_label, App, ConnState, Tab};
use crate::kb::kb::{ContainmentLevel, Zone};

pub fn draw(f: &mut Frame, app: &mut App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(1),
        ])
        .split(f.size());

    draw_header(f, app, root[0]);
    draw_tabs(f, app, root[1]);

    match app.tab {
        Tab::Processes => draw_processes(f, app, root[2]),
        Tab::Alerts => draw_alerts(f, app, root[2]),
        Tab::Activity => draw_activity(f, app, root[2]),
        Tab::Query => draw_query(f, app, root[2]),
    }

    draw_footer(f, app, root[3]);

    if let Some(pc) = app.pending_containment.clone() {
        draw_containment_modal(f, &pc);
    }
    if app.show_help {
        draw_help(f);
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let (badge, badge_style) = match &app.conn {
        ConnState::Connecting => ("CONNECTING…", Style::default().fg(Color::Yellow)),
        ConnState::Live => (
            "LIVE",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ),
        ConnState::Demo => (
            "OFFLINE — DEMO DATA",
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
        ),
        ConnState::Offline(_) => (
            "OFFLINE",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    };

    let mut lines = vec![Line::from(vec![
        Span::styled(
            "KERNEL BORDERLANDS",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  Operator Console   "),
        Span::styled(format!("[{badge}]"), badge_style),
    ])];
    if let ConnState::Offline(reason) = &app.conn {
        lines.push(Line::from(Span::styled(
            format!("kbd unreachable: {reason}"),
            Style::default().fg(Color::DarkGray),
        )));
    } else if let Some((msg, _)) = &app.status_msg {
        lines.push(Line::from(Span::styled(
            msg.clone(),
            Style::default().fg(Color::DarkGray),
        )));
    }
    let left = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(left, cols[0]);

    let stats_block = Block::default().borders(Borders::ALL).title("Telemetry");
    let inner = stats_block.inner(cols[1]);
    f.render_widget(stats_block, cols[1]);

    let stats_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(inner);

    let stats_text = match &app.stats {
        Some(s) => format!(
            "events/sec: {:.1}    active processes: {}    zones: {} SAFE / {} SUS / {} BORDER",
            s.events_per_second,
            s.active_processes,
            app.processes.iter().filter(|p| p.zone == Zone::Safe as i32).count(),
            app.processes.iter().filter(|p| p.zone == Zone::Suspicious as i32).count(),
            app.processes.iter().filter(|p| p.zone == Zone::Borderlands as i32).count(),
        ),
        None => "waiting for telemetry…".to_string(),
    };
    f.render_widget(Paragraph::new(stats_text), stats_rows[0]);

    let data: Vec<u64> = app.eps_history.iter().map(|v| *v as u64).collect();
    let spark = Sparkline::default()
        .data(&data)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(spark, stats_rows[1]);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::ALL.iter().map(|t| Line::from(t.title())).collect();
    let idx = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title("Views  (Tab / Shift+Tab)"))
        .select(idx)
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, area);
}

fn zone_style(zone_val: i32) -> Style {
    match Zone::try_from(zone_val).unwrap_or(Zone::Safe) {
        Zone::Safe => Style::default().fg(Color::Green),
        Zone::Suspicious => Style::default().fg(Color::Yellow),
        Zone::Borderlands => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

fn containment_style(level_val: i32) -> Style {
    match ContainmentLevel::try_from(level_val).unwrap_or(ContainmentLevel::None) {
        ContainmentLevel::None => Style::default().fg(Color::DarkGray),
        ContainmentLevel::Cgroup => Style::default().fg(Color::Blue),
        ContainmentLevel::Seccomp => Style::default().fg(Color::Magenta),
        ContainmentLevel::Namespace => Style::default().fg(Color::Yellow),
        ContainmentLevel::Terminate => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

fn severity_style(sev: &str) -> Style {
    match sev.to_lowercase().as_str() {
        "critical" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        "high" => Style::default().fg(Color::Red),
        "medium" => Style::default().fg(Color::Yellow),
        _ => Style::default().fg(Color::Gray),
    }
}

fn draw_processes(f: &mut Frame, app: &mut App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(68), Constraint::Percentage(32)])
        .split(area);

    let header = Row::new(vec!["PID", "COMM", "ZONE", "SCORE", "UID", "CONTAINMENT"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let visible = app.visible_processes();
    let rows: Vec<Row> = visible
        .iter()
        .map(|p| {
            Row::new(vec![
                Cell::from(p.pid.to_string()),
                Cell::from(p.comm.clone()),
                Cell::from(zone_label(p.zone)).style(zone_style(p.zone)),
                Cell::from(format!("{:.2}", p.score)),
                Cell::from(p.uid.to_string()),
                Cell::from(containment_label(p.containment)).style(containment_style(p.containment)),
            ])
        })
        .collect();

    let title = if app.filter_active || !app.filter.is_empty() {
        format!("Active Monitored Processes — filter: {}_", app.filter)
    } else {
        format!("Active Monitored Processes ({})", visible.len())
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Percentage(28),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title))
    .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");

    f.render_stateful_widget(table, cols[0], &mut app.table_state);

    let detail = match app.selected_process() {
        Some(p) => Paragraph::new(vec![
            Line::from(vec![Span::raw("PID:  "), Span::raw(p.pid.to_string())]),
            Line::from(vec![Span::raw("PPID: "), Span::raw(p.ppid.to_string())]),
            Line::from(vec![Span::raw("COMM: "), Span::styled(p.comm.clone(), Style::default().add_modifier(Modifier::BOLD))]),
            Line::from(vec![Span::raw("UID:  "), Span::raw(p.uid.to_string())]),
            Line::from(vec![Span::raw("ZONE: "), Span::styled(zone_label(p.zone), zone_style(p.zone))]),
            Line::from(vec![Span::raw("SCORE: "), Span::raw(format!("{:.2}", p.score))]),
            Line::from(vec![
                Span::raw("CONTAINMENT: "),
                Span::styled(containment_label(p.containment), containment_style(p.containment)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "[c] set containment level",
                Style::default().fg(Color::DarkGray),
            )),
        ]),
        None => Paragraph::new("No process selected."),
    }
    .block(Block::default().borders(Borders::ALL).title("Detail"))
    .wrap(Wrap { trim: true });
    f.render_widget(detail, cols[1]);
}

fn draw_alerts(f: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .alerts
        .iter()
        .map(|a| {
            let head = Line::from(vec![
                Span::styled(format!("[{}] ", a.severity.to_uppercase()), severity_style(&a.severity)),
                Span::styled(a.alert_type.clone(), Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!(
                    "  pid={} comm={} confidence={:.2}",
                    a.pid, a.comm, a.confidence
                )),
            ]);
            let mut lines = vec![head];
            if app.alert_expanded {
                for ev in &a.evidence {
                    lines.push(Line::from(Span::styled(
                        format!("    • {ev}"),
                        Style::default().fg(Color::DarkGray),
                    )));
                }
            }
            ListItem::new(lines)
        })
        .collect();

    let title = format!(
        "Live Alert Feed ({})  —  [Enter] {} evidence",
        app.alerts.len(),
        if app.alert_expanded { "collapse" } else { "expand" }
    );
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::default().bg(Color::DarkGray));
    f.render_stateful_widget(list, area, &mut app.alert_list_state);
}

fn draw_activity(f: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .events
        .iter()
        .map(|e| {
            let delta_style = if e.score_delta >= 0.0 {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Green)
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<24}", e.event_type), Style::default().fg(Color::Cyan)),
                Span::raw(format!("pid={:<7} comm={:<16}", e.pid, e.comm)),
                Span::styled(format!("Δscore={:+.2}", e.score_delta), delta_style),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Agent / Kernel Activity Feed ({})", app.events.len())),
        )
        .highlight_style(Style::default().bg(Color::DarkGray));
    f.render_stateful_widget(list, area, &mut app.activity_list_state);
}

fn draw_query(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    let lines: Vec<Line> = app
        .query_console
        .iter()
        .rev()
        .take((rows[0].height as usize).saturating_sub(2))
        .rev()
        .map(|l| Line::from(l.as_str()))
        .collect();
    let console = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Query Console"))
        .wrap(Wrap { trim: false });
    f.render_widget(console, rows[0]);

    let input = Paragraph::new(Line::from(vec![
        Span::styled("> ", Style::default().fg(Color::Cyan)),
        Span::raw(app.query_input.as_str()),
        Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
    ]))
    .block(Block::default().borders(Borders::ALL).title("type a command, Enter to run — 'help' for commands"));
    f.render_widget(input, rows[1]);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints = match app.tab {
        Tab::Processes if app.filter_active => "type to filter · Enter/Esc done",
        Tab::Processes => "↑/↓ select · / filter · c containment · Tab switch view · ? help · q quit",
        Tab::Alerts => "↑/↓ scroll · Enter expand evidence · Tab switch view · ? help · q quit",
        Tab::Activity => "↑/↓ scroll · Tab switch view · ? help · q quit",
        Tab::Query => "type command · Enter run · ↑/↓ history · Tab switch view · Ctrl+C quit",
    };
    f.render_widget(
        Paragraph::new(hints).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn centered_rect(pct_x: u16, pct_y: u16, r: Rect) -> Rect {
    let popup_y = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(popup_y[1])[1]
}

fn draw_containment_modal(f: &mut Frame, pc: &crate::app::PendingContainment) {
    let area = centered_rect(50, 40, f.size());
    f.render_widget(Clear, area);

    let mut lines = vec![
        Line::from(vec![
            Span::raw("Target: "),
            Span::styled(format!("pid {} ({})", pc.pid, pc.comm), Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
    ];

    match pc.level {
        None => {
            lines.push(Line::from("Select containment level:"));
            lines.push(Line::from("  [0] NONE"));
            lines.push(Line::from(Span::styled("  [1] CGROUP", Style::default().fg(Color::Blue))));
            lines.push(Line::from(Span::styled("  [2] SECCOMP", Style::default().fg(Color::Magenta))));
            lines.push(Line::from(Span::styled("  [3] NAMESPACE", Style::default().fg(Color::Yellow))));
            lines.push(Line::from(Span::styled(
                "  [4] TERMINATE",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Esc cancel", Style::default().fg(Color::DarkGray))));
        }
        Some(level) => {
            let danger = matches!(level, ContainmentLevel::Terminate);
            let style = if danger {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default().add_modifier(Modifier::BOLD)
            };
            lines.push(Line::from(vec![
                Span::raw("Confirm setting containment to "),
                Span::styled(containment_label(level as i32), style),
                Span::raw(" ?"),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from("  [y] confirm      [n] back"));
            if danger {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "⚠ TERMINATE will kill the process.",
                    Style::default().fg(Color::Red),
                )));
            }
        }
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Containment Action")
        .border_style(Style::default().fg(Color::Yellow));
    let p = Paragraph::new(lines).block(block).alignment(Alignment::Left);
    f.render_widget(p, area);
}

fn draw_help(f: &mut Frame) {
    let area = centered_rect(60, 70, f.size());
    f.render_widget(Clear, area);
    let text = vec![
        Line::from(Span::styled("kb-tui — keybindings", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("Global"),
        Line::from("  Tab / Shift+Tab   switch views"),
        Line::from("  ?                 toggle this help"),
        Line::from("  Ctrl+C            quit"),
        Line::from(""),
        Line::from("Processes"),
        Line::from("  ↑/↓ or j/k        move selection"),
        Line::from("  /                 filter by process name"),
        Line::from("  c                 set containment level for selected process"),
        Line::from("  q                 quit"),
        Line::from(""),
        Line::from("Alerts / Agent Activity"),
        Line::from("  ↑/↓ or j/k        scroll"),
        Line::from("  Enter             expand/collapse alert evidence"),
        Line::from(""),
        Line::from("Query Console"),
        Line::from("  type + Enter      run a command ('help' lists them)"),
        Line::from("  ↑/↓               command history"),
        Line::from(""),
        Line::from(Span::styled("Press ? or Esc to close", Style::default().fg(Color::DarkGray))),
    ];
    let block = Block::default().borders(Borders::ALL).title("Help");
    f.render_widget(Paragraph::new(text).block(block).wrap(Wrap { trim: true }), area);
}
