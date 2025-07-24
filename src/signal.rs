use std::future::Future;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{info, warn};

/// Waits for a termination signal (SIGINT or SIGTERM)
pub async fn wait_for_signal() {
    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");

    tokio::select! {
        _ = sigint.recv() => {
            info!("Received SIGINT, shutting down");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down");
        }
    }
}

/// Runs a future until a termination signal is received
pub async fn run_until_signal<F, T>(future: F) -> T
where
    F: Future<Output = T>,
{
    tokio::select! {
        result = future => result,
        _ = wait_for_signal() => {
            warn!("Terminating due to signal");
            panic!("Server terminated due to signal");
        }
    }
}