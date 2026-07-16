use std::time::Duration;

use tokio::net::UnixStream;
use tokio::sync::mpsc::UnboundedSender;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

use crate::app::AppEvent;
use crate::kb::kb::kernel_borderlands_client::KernelBorderlandsClient;
use crate::kb::kb::{Empty, EventFilter, Zone, ZoneRequest};

pub const DEFAULT_UDS_PATH: &str = "/run/kb/kba.sock";
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(2000);
const STATS_POLL_INTERVAL: Duration = Duration::from_millis(3000);
const STREAM_RETRY_INTERVAL: Duration = Duration::from_millis(2000);

pub type KbClient = KernelBorderlandsClient<Channel>;

async fn connect_uds(path: &str) -> Result<Channel, tonic::transport::Error> {
    let path = path.to_string();
    Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_| {
            let path = path.clone();
            async move { UnixStream::connect(path).await }
        }))
        .await
}

/// Attempts to connect to `kbd`'s gRPC gateway over the UDS at `/run/kb/kba.sock`.
/// On success, spawns the background streaming/polling tasks that keep the UI fed
/// and returns a client handle for on-demand RPCs (containment, query console).
/// On failure or timeout, falls back to offline demo mode with synthetic data.
pub async fn start(tx: UnboundedSender<AppEvent>) -> Option<KbClient> {
    let connect = tokio::time::timeout(CONNECT_TIMEOUT, connect_uds(DEFAULT_UDS_PATH)).await;

    let channel = match connect {
        Ok(Ok(channel)) => channel,
        Ok(Err(e)) => {
            let _ = tx.send(AppEvent::ConnectionFailed(format!(
                "{DEFAULT_UDS_PATH}: {e}"
            )));
            crate::demo::spawn(tx);
            return None;
        }
        Err(_) => {
            let _ = tx.send(AppEvent::ConnectionFailed(format!(
                "timed out connecting to {DEFAULT_UDS_PATH}"
            )));
            crate::demo::spawn(tx);
            return None;
        }
    };

    let client = KernelBorderlandsClient::new(channel);
    let _ = tx.send(AppEvent::Connected);

    spawn_process_poller(client.clone(), tx.clone());
    spawn_stats_poller(client.clone(), tx.clone());
    spawn_alert_stream(client.clone(), tx.clone());
    spawn_event_stream(client.clone(), tx.clone());

    Some(client)
}

fn spawn_process_poller(mut client: KbClient, tx: UnboundedSender<AppEvent>) {
    tokio::spawn(async move {
        loop {
            let mut all = Vec::new();
            for zone in [Zone::Safe, Zone::Suspicious, Zone::Borderlands] {
                if let Ok(resp) = client.list_zone(ZoneRequest { zone: zone as i32 }).await {
                    let mut stream = resp.into_inner();
                    while let Ok(Some(p)) = stream.message().await {
                        all.push(p);
                    }
                }
            }
            if tx.send(AppEvent::ProcessSnapshot(all)).is_err() {
                return;
            }
            tokio::time::sleep(PROCESS_POLL_INTERVAL).await;
        }
    });
}

fn spawn_stats_poller(mut client: KbClient, tx: UnboundedSender<AppEvent>) {
    tokio::spawn(async move {
        loop {
            if let Ok(resp) = client.get_system_stats(Empty {}).await {
                if tx.send(AppEvent::Stats(resp.into_inner())).is_err() {
                    return;
                }
            }
            tokio::time::sleep(STATS_POLL_INTERVAL).await;
        }
    });
}

fn spawn_alert_stream(mut client: KbClient, tx: UnboundedSender<AppEvent>) {
    tokio::spawn(async move {
        loop {
            if let Ok(resp) = client
                .stream_alerts(EventFilter { event_types: vec![] })
                .await
            {
                let mut stream = resp.into_inner();
                while let Ok(Some(alert)) = stream.message().await {
                    if tx.send(AppEvent::Alert(alert)).is_err() {
                        return;
                    }
                }
            }
            tokio::time::sleep(STREAM_RETRY_INTERVAL).await;
        }
    });
}

fn spawn_event_stream(mut client: KbClient, tx: UnboundedSender<AppEvent>) {
    tokio::spawn(async move {
        loop {
            if let Ok(resp) = client
                .stream_events(EventFilter { event_types: vec![] })
                .await
            {
                let mut stream = resp.into_inner();
                while let Ok(Some(ev)) = stream.message().await {
                    if tx.send(AppEvent::KbEvent(ev)).is_err() {
                        return;
                    }
                }
            }
            tokio::time::sleep(STREAM_RETRY_INTERVAL).await;
        }
    });
}
