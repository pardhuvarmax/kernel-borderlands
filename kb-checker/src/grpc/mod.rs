use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;

use crate::checker::checker_status_server::{CheckerStatus, CheckerStatusServer};
use crate::checker::{StatusRequest, StatusResponse};

#[derive(Debug, Clone)]
pub struct CheckerState {
    pub healthy: bool,
    pub last_checked: String,
    pub errors: Vec<String>,
}

impl Default for CheckerState {
    fn default() -> Self {
        Self {
            healthy: true,
            last_checked: "never".to_string(),
            errors: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct CheckerStatusService {
    state: Arc<Mutex<CheckerState>>,
}

impl CheckerStatusService {
    pub fn new(state: Arc<Mutex<CheckerState>>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl CheckerStatus for CheckerStatusService {
    async fn get_status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let state = self.state.lock().unwrap();
        Ok(Response::new(StatusResponse {
            healthy: state.healthy,
            last_checked: state.last_checked.clone(),
            errors: state.errors.clone(),
        }))
    }
}

pub async fn start_grpc_server(
    uds_path: &str,
    state: Arc<Mutex<CheckerState>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Clean up existing socket file if it exists
    if std::path::Path::new(uds_path).exists() {
        let _ = std::fs::remove_file(uds_path);
    }

    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(uds_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    println!("[GRPC] Starting Checker gRPC Status Server on UDS: {}...", uds_path);
    let uds = UnixListener::bind(uds_path)?;
    let uds_stream = UnixListenerStream::new(uds);

    tonic::transport::Server::builder()
        .add_service(CheckerStatusServer::new(CheckerStatusService::new(state)))
        .serve_with_incoming(uds_stream)
        .await?;

    Ok(())
}
