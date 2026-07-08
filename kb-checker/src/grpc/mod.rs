use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

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
    addr: std::net::SocketAddr,
    state: Arc<Mutex<CheckerState>>,
) -> Result<(), tonic::transport::Error> {
    println!("[GRPC] Starting Checker gRPC Status Server on {}...", addr);
    tonic::transport::Server::builder()
        .add_service(CheckerStatusServer::new(CheckerStatusService::new(state)))
        .serve(addr)
        .await
}
