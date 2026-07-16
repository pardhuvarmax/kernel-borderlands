mod app;
mod demo;
mod grpc;
mod kb;
mod query;
mod ui;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use futures::StreamExt;
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::Terminal;
use tokio::sync::{mpsc, Mutex};

use app::{Action, App, AppEvent};
use grpc::KbClient;
use kb::kb::ContainmentRequest;

type SharedClient = Arc<Mutex<Option<KbClient>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run(&mut terminal).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if let Err(err) = result {
        eprintln!("{err:?}");
    }
    Ok(())
}

async fn run<B: Backend>(terminal: &mut Terminal<B>) -> io::Result<()> {
    let mut app = App::new();
    let (tx, mut rx) = mpsc::unbounded_channel::<AppEvent>();

    let client: SharedClient = Arc::new(Mutex::new(None));
    {
        let tx = tx.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let c = grpc::start(tx).await;
            *client.lock().await = c;
        });
    }

    let mut events = EventStream::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(250));

    loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;

        tokio::select! {
            _ = ticker.tick() => {
                app.tick();
            }
            maybe_event = events.next() => {
                if let Some(Ok(Event::Key(key))) = maybe_event {
                    if key.kind == KeyEventKind::Press {
                        match app.handle_key(key) {
                            Action::None => {}
                            Action::Quit => app.should_quit = true,
                            Action::SubmitContainment { pid, level, reason } => {
                                spawn_containment(pid, level, reason, tx.clone(), client.clone());
                            }
                            Action::RunQuery(cmd) => {
                                spawn_query(cmd, tx.clone(), client.clone());
                            }
                        }
                    }
                }
            }
            Some(ev) = rx.recv() => {
                app.apply_event(ev);
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn spawn_containment(
    pid: u32,
    level: kb::kb::ContainmentLevel,
    reason: String,
    tx: mpsc::UnboundedSender<AppEvent>,
    client: SharedClient,
) {
    tokio::spawn(async move {
        let maybe_client = client.lock().await.clone();
        let event = match maybe_client {
            Some(mut c) => {
                let request = ContainmentRequest {
                    pid,
                    level: level as i32,
                    reason,
                };
                match c.set_containment(request).await {
                    Ok(resp) => AppEvent::ContainmentResult {
                        pid,
                        success: resp.into_inner().success,
                        message: "containment request applied".to_string(),
                    },
                    Err(e) => AppEvent::ContainmentResult {
                        pid,
                        success: false,
                        message: e.to_string(),
                    },
                }
            }
            None => AppEvent::ContainmentResult {
                pid,
                success: true,
                message: "simulated — offline/demo mode, not persisted".to_string(),
            },
        };
        let _ = tx.send(event);
    });
}

fn spawn_query(cmd: String, tx: mpsc::UnboundedSender<AppEvent>, client: SharedClient) {
    tokio::spawn(async move {
        let maybe_client = client.lock().await.clone();
        let lines = query::run(maybe_client, &cmd).await;
        let _ = tx.send(AppEvent::QueryResult(lines));
    });
}
