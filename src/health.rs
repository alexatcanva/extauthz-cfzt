use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug)]
pub struct HealthState {
    validator_ready: AtomicBool,
}

/// READY_RESPONSE is the HTTP 200 OK response for the /readyz endpoint.
const READY_RESPONSE: &str = concat!(
    "HTTP/1.1 200 OK\r\n",
    "Content-Length: 2\r\n",
    "Content-Type: text/plain\r\n",
    "\r\n",
    "OK"
);

/// NOT_READY_RESPONSE is the HTTP 503 Service Unavailable response for the
/// /readyz endpoint.
const NOT_READY_RESPONSE: &str = concat!(
    "HTTP/1.1 503 Service Unavailable\r\n",
    "Content-Length: 9\r\n",
    "Content-Type: text/plain\r\n",
    "\r\n",
    "NOT READY"
);

/// NOT_FOUND_RESPONSE is the HTTP 404 Not Found response for the /readyz
/// endpoint.
const NOT_FOUND_RESPONSE: &str = concat!(
    "HTTP/1.1 404 Not Found\r\n",
    "Content-Length: 9\r\n",
    "Content-Type: text/plain\r\n",
    "\r\n",
    "NOT FOUND"
);

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

/// HealthState manages the readiness state of the validator.
/// It uses an atomic boolean to indicate whether the validator is ready.
/// This is used by the health server to respond to readiness checks.
/// The state can be marked as ready or checked for readiness.
/// It is thread-safe and can be shared across multiple threads or tasks.
impl HealthState {
    pub fn new() -> Self {
        HealthState {
            validator_ready: AtomicBool::new(false),
        }
    }

    pub fn mark_validator_ready(&self) {
        self.validator_ready.store(true, Ordering::SeqCst);
    }

    pub fn is_validator_ready(&self) -> bool {
        self.validator_ready.load(Ordering::SeqCst)
    }
}

/// run_health_server starts a health server that listens for HTTP requests
/// on the specified address. It handles requests for /readyz and /healthz
/// endpoints.
/// It responds with [READY_RESPONSE] if the validator is ready,
/// [NOT_READY_RESPONSE] if it is not ready, and [NOT_FOUND_RESPONSE] for any other
/// requests.
pub async fn run_health_server(state: Arc<HealthState>, port: u16) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    log::info!("Health server listening on 0.0.0.0:{}", port);

    loop {
        let (socket, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                log::error!("Error accepting connection: {}", e);
                continue;
            }
        };

        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, state_clone).await {
                log::error!("Error handling connection: {}", e);
            }
        });
    }
}

/// handle_connection processes a single incoming connection.
/// It reads the request line, checks the endpoint, and responds accordingly.
/// It responds with [READY_RESPONSE] if the validator is ready,
/// [NOT_READY_RESPONSE] if it is not ready, and [NOT_FOUND_RESPONSE] for any other
/// requests.
async fn handle_connection(mut socket: TcpStream, state: Arc<HealthState>) -> Result<()> {
    let (reader, mut writer) = socket.split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    reader.read_line(&mut line).await?;

    let response = match line.as_str() {
        line if line.contains("GET /readyz") => {
            log::debug!("Received readyz request");
            if state.is_validator_ready() {
                READY_RESPONSE
            } else {
                NOT_READY_RESPONSE
            }
        }
        line if line.contains("GET /healthz") => {
            log::debug!("Received healthz request");
            READY_RESPONSE
        }
        line => {
            log::debug!("Received unknown request: {}", line.trim());
            NOT_FOUND_RESPONSE
        }
    };

    writer.write_all(response.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    #[test]
    fn test_health_state_new() {
        let state = HealthState::new();
        assert!(!state.is_validator_ready());
    }

    #[test]
    fn test_health_state_default() {
        let state = HealthState::default();
        assert!(!state.is_validator_ready());
    }

    #[test]
    fn test_health_state_mark_ready() {
        let state = HealthState::new();
        assert!(!state.is_validator_ready());

        state.mark_validator_ready();
        assert!(state.is_validator_ready());
    }

    #[test]
    fn test_health_state_thread_safety() {
        let state = Arc::new(HealthState::new());
        let state_clone = Arc::clone(&state);

        let handle = std::thread::spawn(move || {
            state_clone.mark_validator_ready();
        });

        handle.join().unwrap();
        assert!(state.is_validator_ready());
    }

    #[tokio::test]
    async fn test_readyz_endpoint_not_ready() {
        let state = Arc::new(HealthState::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Start server in background
        let server_state = Arc::clone(&state);
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_connection(socket, server_state).await.unwrap();
        });

        // Connect and send request
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        // Read response
        let mut buffer = [0; 1024];
        let n = timeout(Duration::from_secs(1), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8_lossy(&buffer[..n]);

        assert!(response.contains("503 Service Unavailable"));
        assert!(response.contains("NOT READY"));
    }

    #[tokio::test]
    async fn test_readyz_endpoint_ready() {
        let state = Arc::new(HealthState::new());
        state.mark_validator_ready();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Start server in background
        let server_state = Arc::clone(&state);
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_connection(socket, server_state).await.unwrap();
        });

        // Connect and send request
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        // Read response
        let mut buffer = [0; 1024];
        let n = timeout(Duration::from_secs(1), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8_lossy(&buffer[..n]);

        assert!(response.contains("200 OK"));
        assert!(response.contains("OK"));
        assert!(!response.contains("NOT READY"));
    }

    #[tokio::test]
    async fn test_healthz_endpoint() {
        let state = Arc::new(HealthState::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Start server in background
        let server_state = Arc::clone(&state);
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_connection(socket, server_state).await.unwrap();
        });

        // Connect and send request
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        // Read response
        let mut buffer = [0; 1024];
        let n = timeout(Duration::from_secs(1), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8_lossy(&buffer[..n]);

        assert!(response.contains("200 OK"));
        assert!(response.contains("OK"));
    }

    #[tokio::test]
    async fn test_unknown_endpoint() {
        let state = Arc::new(HealthState::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Start server in background
        let server_state = Arc::clone(&state);
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_connection(socket, server_state).await.unwrap();
        });

        // Connect and send request
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        // Read response
        let mut buffer = [0; 1024];
        let n = timeout(Duration::from_secs(1), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8_lossy(&buffer[..n]);

        assert!(response.contains("404 Not Found"));
        assert!(response.contains("NOT FOUND"));
    }

    #[tokio::test]
    async fn test_malformed_request() {
        let state = Arc::new(HealthState::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Start server in background
        let server_state = Arc::clone(&state);
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_connection(socket, server_state).await.unwrap();
        });

        // Connect and send malformed request
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"INVALID REQUEST\r\n").await.unwrap();

        // Read response
        let mut buffer = [0; 1024];
        let n = timeout(Duration::from_secs(1), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8_lossy(&buffer[..n]);

        assert!(response.contains("404 Not Found"));
        assert!(response.contains("NOT FOUND"));
    }

    #[test]
    fn test_response_constants() {
        // Test that responses have correct content-length
        assert!(READY_RESPONSE.contains("Content-Length: 2"));
        assert!(READY_RESPONSE.contains("OK"));

        assert!(NOT_READY_RESPONSE.contains("Content-Length: 9"));
        assert!(NOT_READY_RESPONSE.contains("NOT READY"));

        assert!(NOT_FOUND_RESPONSE.contains("Content-Length: 9"));
        assert!(NOT_FOUND_RESPONSE.contains("NOT FOUND"));
    }

    #[tokio::test]
    async fn test_concurrent_requests() {
        let state = Arc::new(HealthState::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Start server
        let server_state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let state_clone = Arc::clone(&server_state);
                tokio::spawn(async move {
                    handle_connection(socket, state_clone).await.unwrap();
                });
            }
        });

        // Send multiple concurrent requests
        let mut handles = vec![];
        for i in 0..10 {
            let addr_clone = addr;
            let handle = tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr_clone).await.unwrap();
                let endpoint = if i % 2 == 0 { "/readyz" } else { "/healthz" };
                let request = format!("GET {} HTTP/1.1\r\nHost: localhost\r\n\r\n", endpoint);
                stream.write_all(request.as_bytes()).await.unwrap();

                let mut buffer = [0; 1024];
                let n = timeout(Duration::from_secs(1), stream.read(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
                String::from_utf8_lossy(&buffer[..n]).to_string()
            });
            handles.push(handle);
        }

        // Wait for all requests to complete
        for handle in handles {
            let response = handle.await.unwrap();
            assert!(response.contains("HTTP/1.1"));
        }
    }
}
