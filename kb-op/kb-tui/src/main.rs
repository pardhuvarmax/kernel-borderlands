mod app;
mod dash; // Registers your new Vite bundle server
mod demo;
mod grpc;
mod kb;
mod query;
mod ui;

use std::io;
use std::process::Stdio; // Required for cleaning background pipes
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use futures::StreamExt;
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::Terminal;
use std::io::IsTerminal;
use tokio::process::Command; // Added Tokio process management capabilities
use tokio::sync::{mpsc, Mutex};

use app::{Action, App, AppEvent};
use grpc::KbClient;
use kb::kb::ContainmentRequest;

type SharedClient = Arc<Mutex<Option<KbClient>>>;


/// Locates the `mcp-server` binary this build ships alongside. Packages
/// (.deb / Arch) install to /usr/bin, `make install` defaults to
/// /usr/local/bin, so a single hardcoded path can't be right for both —
/// prefer the directory kbopd itself runs from, then the two known
/// install prefixes.
fn mcp_server_path() -> std::path::PathBuf {
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("mcp-server")));
    sibling
        .into_iter()
        .chain(["/usr/bin/mcp-server", "/usr/local/bin/mcp-server"].map(Into::into))
        .find(|p| p.is_file())
        .unwrap_or_else(|| "/usr/local/bin/mcp-server".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 2. Guard Check: Are we running in a real interactive terminal shell?
    if !io::stdout().is_terminal() {
        println!("⚙️ No interactive TTY detected. Booting kbopd in headless background daemon mode...");
        return run_headless().await;
    }

    // --- Interactive Mode Sequence (When called via SSH Wrapper script) ---
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

/// 3. Headless Mode Execution Path (For Systemd Service)
async fn run_headless() -> Result<(), Box<dyn std::error::Error>> {
    let (tx, mut rx) = mpsc::unbounded_channel::<AppEvent>();

    // Start Embedded Vite Dashboard Server
    let dashboard_port = 8082;
    let dashboard_tx = tx.clone();
    tokio::spawn(async move {
        let _ = dash::start_server(dashboard_port, dashboard_tx).await;
    });
    println!("🚀 Vite Dashboard Server listening on http://localhost:{}", dashboard_port);

    // Initialize Background MCP Server. /usr/local/bin — matches the
    // top-level Makefile's real install target (`install -Dm755
    // bin/mcp-server /usr/local/bin/mcp-server`); this previously pointed
    // at /opt/kb/bin/mcp-server, a stale, unrelated manual-test location
    // that happened to still exist on disk and mask the mismatch.
    let mut mcp_child = Command::new(mcp_server_path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Fatal: Could not initialize background MCP sub-process");
    println!("✅ Background MCP server spawned successfully.");

    // Drive internal background events indefinitely or handle systemd signals
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("🛑 Received termination signal from Systemd.");
        }
        // Keep the state router tick alive
        _ = async {
            loop {
                // Drain any incoming background API events to keep channel clear
                let _ = rx.recv().await; 
            }
        } => {}
    }

    println!("🧹 Tearing down background service targets...");
    let _ = mcp_child.kill().await;
    Ok(())
}

async fn run<B: Backend>(terminal: &mut Terminal<B>) -> io::Result<()> {
    let mut app = App::new();
    let (tx, mut rx) = mpsc::unbounded_channel::<AppEvent>();

    // ---------------------------------------------------------
    // 1. Initialize Embedded Vite Dashboard Server
    // ---------------------------------------------------------
    let dashboard_port = 8082;
    let dashboard_tx = tx.clone(); // Pass access down to the web thread pool
    tokio::spawn(async move {
        let _ = dash::start_server(dashboard_port, dashboard_tx).await;
    });

    // ---------------------------------------------------------
    // 2. Initialize Background MCP Server Component
    // ---------------------------------------------------------
    // Stdio::null() isolates standard stdout lines away from Crossterm views.
    // Same /usr/local/bin/mcp-server path as run_headless() above — this was
    // previously "/opt/bin/mcp-server" (missing "/kb/", and also the wrong
    // base dir), a second, independently-wrong hardcoded path that never
    // matched either the headless-mode path above or the real install
    // location.
    let mut mcp_child = Command::new(mcp_server_path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Fatal: Could not initialize background MCP sub-process");

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
            // ---------------------------------------------------------
            // 3. Graceful Sub-process Termination Loop
            // ---------------------------------------------------------
            let _ = mcp_child.kill().await;
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
