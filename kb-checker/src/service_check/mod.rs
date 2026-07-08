use std::time::Duration;
use reqwest::Client;
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Channel};
use tower::service_fn;

use crate::grpc_health_v1::health_client::HealthClient;
use crate::grpc_health_v1::HealthCheckRequest;

const DEFAULT_UDS_PATH: &str = "/run/kb/kba.sock";
const RAY_API_URL: &str = "http://localhost:8265/api/jobs";

// Connect helper to gRPC server over Unix Domain Socket
pub async fn connect_uds_grpc() -> Result<Channel, tonic::transport::Error> {
    Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(|_| async {
            UnixStream::connect(DEFAULT_UDS_PATH).await
        }))
        .await
}

// TASK 2: Control Plane Availability Audit (gRPC Health Check)
pub async fn check_control_plane_health() -> Result<(), Box<dyn std::error::Error>> {
    check_control_plane_health_at(DEFAULT_UDS_PATH).await
}

pub async fn check_control_plane_health_at(uds_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[HEALTH] Performing gRPC availability audit over UDS: {}...", uds_path);
    let path = uds_path.to_string();
    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_| {
            let path_clone = path.clone();
            async move {
                UnixStream::connect(path_clone).await
            }
        }))
        .await?;
    let mut client = HealthClient::new(channel);

    let request = HealthCheckRequest {
        service: "kb.KernelBorderlands".to_string(),
    };

    // Enforce a strict 100ms deadline
    let response = tokio::time::timeout(
        Duration::from_millis(100),
        client.check(request)
    ).await??;

    let status = response.into_inner().status;
    if status == 1 { // SERVING
        println!("[HEALTH] Control plane gRPC check: SERVING");
        Ok(())
    } else {
        Err(format!("Control plane reported non-serving status: {:?}", status).into())
    }
}

// TASK 3: AADS Swarm Status Verification (Ray Cluster API)
pub async fn check_swarm_health() -> Result<(), Box<dyn std::error::Error>> {
    check_swarm_health_at(RAY_API_URL).await
}

pub async fn check_swarm_health_at(api_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[SWARM] Querying AADS Swarm Ray cluster status at {}...", api_url);
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;

    let mut attempts = 0;
    loop {
        attempts += 1;
        match client.get(api_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    println!("[SWARM] Ray cluster REST API check: ONLINE (attempt {})", attempts);
                    return Ok(());
                } else if attempts >= 3 {
                    return Err(format!("Ray cluster API returned status: {} after 3 attempts", response.status()).into());
                }
            }
            Err(e) => {
                if attempts >= 3 {
                    return Err(format!("Ray cluster connection failed after 3 attempts: {:?}", e).into());
                }
            }
        }
        println!("[SWARM] [RETRY] Ray check failed. Retrying in 2 seconds (attempt {} of 3)...", attempts);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
