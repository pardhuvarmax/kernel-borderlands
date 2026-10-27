use axum::{
    body::Body,
    extract::State,
    http::{header, Response, StatusCode, Uri},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use rust_embed::RustEmbed;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use serde::Deserialize;

// Pull your application's communication entities
use crate::app::AppEvent;

// 1. Embed your Vite dashboard production build folder into the compiled binary
#[derive(RustEmbed)]
#[folder = "../kb-dashboard/dist/"] // Ensure this points correctly to your Vite dist folder
struct Assets;

// 2. State payload shared across concurrent web server workers
#[derive(Clone)]
struct AppState {
    tx: mpsc::UnboundedSender<AppEvent>,
}

// 3. Payload model parsing input queries from the Vite interface
#[derive(Deserialize)]
struct ContainmentPayload {
    pid: u32,
    level: i32,
    reason: String,
}

/// Dynamic file extractor serving static files or executing SPA routes
async fn serve_assets(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let file_path = if path.is_empty() { "index.html" } else { path };

    match Assets::get(file_path) {
        Some(content) => {
            let mime = mime_guess::from_path(file_path).first_or_octet_stream();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(Body::from(content.data))
                .unwrap()
        }
        None => {
            // Fallback router strategy: yields index.html if asset is a frontend router URL
            let index = Assets::get("index.html").expect("index.html missing from embedded dist");
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html")
                .body(Body::from(index.data))
                .unwrap()
        }
    }
}

/// Web panel endpoint mapping dashboard actions back into the main TUI pipeline
async fn handle_dashboard_containment(
    State(state): State<AppState>,
    Json(payload): Json<ContainmentPayload>,
) -> impl IntoResponse {
    // Send containment result state into the core tokio::select loop inside main.rs
    let _ = state.tx.send(AppEvent::ContainmentResult {
        pid: payload.pid,
        success: true,
        message: format!("Triggered via dashboard network interface: {}", payload.reason),
    });

    StatusCode::OK
}

/// Master initialization loop to spin up the web engine background worker
pub async fn start_server(port: u16, tx: mpsc::UnboundedSender<AppEvent>) -> Result<(), Box<dyn std::error::Error>> {
    let shared_state = AppState { tx };

    // Structure your API paths entirely above your fallback handler
    let app = Router::new()
        .route("/api/containment", post(handle_dashboard_containment))
        .fallback(get(serve_assets))
        .with_state(shared_state);
        
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;
    
    axum::serve(listener, app).await?;
    
    Ok(())
}
