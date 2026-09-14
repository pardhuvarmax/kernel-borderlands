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
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        // Real grpc_health_v1 semantics: NOT_FOUND for an unregistered
        // service name, matching kb-control-plane's real health server.
        // Previously ignored the request entirely and always returned
        // SERVING — which is exactly how a real service-name mismatch
        // between kb-checker's client and kbd's server (found via a real
        // boot test: kb-checker was querying "kb.KernelBorderlands",
        // kbd only ever registers "kernel-borderlands") went undetected
        // by this suite for as long as it did.
        if request.into_inner().service == "kernel-borderlands" {
            Ok(Response::new(HealthCheckResponse { status: 1 })) // SERVING
        } else {
            Err(Status::not_found("unknown service"))
        }
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

// Regression test for the real service-name mismatch bug: this fails
// against the corrected assertion above (the client now sends
// "kernel-borderlands") the same way it would have failed against the
// old, wrong "kb.KernelBorderlands" — pinning the exact string kb-checker
// must send so it can't silently drift from kbd's real ServiceName const
// (kb-control-plane/internal/controlplane/controlplane.go) again.
#[tokio::test]
async fn test_grpc_health_check_uses_kbd_real_service_name() {
    let socket_path = "/tmp/test-kba-service-name.sock";
    if Path::new(socket_path).exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    let uds = UnixListener::bind(socket_path).unwrap();
    let uds_stream = UnixListenerStream::new(uds);

    let server_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(HealthServer::new(MockHealthService))
            .serve_with_incoming(uds_stream)
            .await
            .unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // MockHealthService only returns SERVING for "kernel-borderlands" —
    // if kb-checker's client ever again sends any other string (e.g. a
    // fully-qualified proto name like "kb.KernelBorderlands"), this
    // fails with the same NotFound the real kbd server would also give.
    let res = check_control_plane_health_at(socket_path).await;
    assert!(
        res.is_ok(),
        "kb-checker must query kbd's real health service name (\"kernel-borderlands\"): {:?}",
        res
    );

    server_handle.abort();
    let _ = std::fs::remove_file(socket_path);
}
