use crate::error::AppResult;
use crate::metrics;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info};

/// Health state structure
#[derive(Debug)]
pub struct HealthState {
    validator_ready: AtomicBool,
}

/// Response constants
const READY_RESPONSE: &str = "OK";
const NOT_READY_RESPONSE: &str = "NOT READY";
const NOT_FOUND_RESPONSE: &str = "NOT FOUND";

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthState {
    /// Create a new health state
    pub fn new() -> Self {
        HealthState {
            validator_ready: AtomicBool::new(false),
        }
    }

    /// Mark the validator as ready
    pub fn mark_validator_ready(&self) {
        self.validator_ready.store(true, Ordering::SeqCst);
        metrics::set_validator_ready(true);
        info!("Validator marked as ready");
    }

    /// Check if the validator is ready
    pub fn is_validator_ready(&self) -> bool {
        self.validator_ready.load(Ordering::SeqCst)
    }
}

/// Run the health server
pub async fn run_health_server(state: Arc<HealthState>, port: u16) -> AppResult<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Health server listening on 0.0.0.0:{}", port);

    // Create a simple TCP listener
    let listener = TcpListener::bind(addr).await?;
    
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Error accepting connection: {}", e);
                continue;
            }
        };
        
        // Create a new state reference for this connection
        let state_clone = Arc::clone(&state);
        
        // Handle connection in a separate task
        tokio::spawn(async move {
            let mut buffer = [0; 1024];
            let n = match stream.read(&mut buffer).await {
                Ok(n) => n,
                Err(e) => {
                    error!("Error reading from socket: {}", e);
                    return;
                }
            };
            
            let request = String::from_utf8_lossy(&buffer[0..n]);
            let uri = request.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("");
            
            debug!("Received request for path: {}", uri);
            
            let response = match uri {
                "/readyz" => {
                    if state_clone.is_validator_ready() {
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}", 
                                READY_RESPONSE.len(), READY_RESPONSE)
                    } else {
                        format!("HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}", 
                                NOT_READY_RESPONSE.len(), NOT_READY_RESPONSE)
                    }
                },
                "/healthz" => {
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}", 
                            READY_RESPONSE.len(), READY_RESPONSE)
                },
                "/metrics" => {
                    let metrics_output = metrics::gather_metrics();
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}", 
                            metrics_output.len(), metrics_output)
                },
                _ => {
                    format!("HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}", 
                            NOT_FOUND_RESPONSE.len(), NOT_FOUND_RESPONSE)
                }
            };
            
            if let Err(e) = stream.write_all(response.as_bytes()).await {
                error!("Error writing to socket: {}", e);
            }
            
            if let Err(e) = stream.flush().await {
                error!("Error flushing socket: {}", e);
            }
        });
    }
}