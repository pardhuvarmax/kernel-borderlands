use std::path::Path;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

use kb_checker::grpc_health_v1::health_server::{Health, HealthServer};
use kb_checker::grpc_health_v1::{HealthCheckRequest, HealthCheckResponse};
use kb_checker::service_check::check_control_plane_health_at;

#[derive(Default)]
struct MockHealthService;

#[tonic::async_trait]
impl Health for MockHealthService {
    type WatchStream = tokio_stream::wrappers::ReceiverStream<Result<HealthCheckResponse, Status>>;

    async fn check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: 1, // SERVING
        }))
    }

    async fn watch(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }
}

#[tokio::test]
async fn test_grpc_health_check_serving() {
    let socket_path = "/tmp/test-kba.sock";
    if Path::new(socket_path).exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    // Start a mock gRPC health server on UDS
    let uds = UnixListener::bind(socket_path).unwrap();
    let uds_stream = UnixListenerStream::new(uds);

    let server_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(HealthServer::new(MockHealthService))
            .serve_with_incoming(uds_stream)
            .await
            .unwrap();
    });

    // Wait a brief moment for the server to bind
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Run the health check client at the mock socket path
    let res = check_control_plane_health_at(socket_path).await;
    assert!(res.is_ok(), "Health check should succeed: {:?}", res);

    // Clean up
    server_handle.abort();
    let _ = std::fs::remove_file(socket_path);
}
