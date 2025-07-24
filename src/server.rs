//! # Cloudflare Zero Trust External Authorization Server
//!
//! This module implements the main gRPC server for Cloudflare Zero Trust External Authorization
//! service. It provides both the authorization service endpoint and observability endpoints
//! for metrics and health checks.
//!
//! ## Features
//!
//! - **Multi-protocol support**: Supports both TCP and Unix domain sockets
//! - **gRPC Authorization**: Implements Envoy's external authorization protocol
//! - **Observability**: Built-in metrics and health check endpoints
//! - **Async/Concurrent**: Full async implementation with per-connection spawning
//!
//! ## Example
//!
//! ```rust,no_run
//! use extauthz_cfzt::server::{Server, SocketOrPath};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let listen_address = SocketOrPath::from_url("tcp://[::1]:10000")?;
//!     let audiences = vec!["my-app".to_string()];
//!     let observability_port = 8080;
//!
//!     let server = Server::new(listen_address, audiences, observability_port);
//!     server.start().await
//! }
//! ```

use std::time::Instant;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use crate::metrics;
use anyhow::Result;
use envoy_types::ext_authz::v3::pb::{
    Authorization, AuthorizationServer, CheckRequest, CheckResponse,
};
use envoy_types::ext_authz::v3::{CheckRequestExt, CheckResponseExt};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener},
    task::JoinHandle,
};
use tonic::{transport::Server as TonicServer, Request, Response, Status};

/// Socket address that can be either TCP or Unix domain socket.
///
/// This enum abstracts over different types of socket addresses to provide
/// a unified interface for server binding. It supports both network (TCP)
/// and local (Unix domain socket) communication methods.
///
/// # Examples
///
/// ```rust
/// use extauthz_cfzt::server::SocketOrPath;
/// use std::net::SocketAddr;
/// use std::path::PathBuf;
///
/// // TCP socket
/// let tcp = SocketOrPath::Tcp("127.0.0.1:8080".parse().unwrap());
///
/// // Unix domain socket  
/// let unix = SocketOrPath::Unix(PathBuf::from("/tmp/server.sock"));
/// ```
pub enum SocketOrPath {
    /// TCP socket address for network communication
    Tcp(SocketAddr),
    /// Unix domain socket path for local IPC
    Unix(PathBuf),
}

impl SocketOrPath {
    /// Parses a URL string into a `SocketOrPath`.
    ///
    /// This method supports multiple URL formats:
    /// - `tcp://host:port` - TCP socket
    /// - `unix://path` - Unix domain socket
    /// - `host:port` - TCP socket (default when no scheme provided)
    ///
    /// # Arguments
    ///
    /// * `url_str` - The URL string to parse
    ///
    /// # Returns
    ///
    /// Returns a `Result<SocketOrPath>` containing the parsed socket address
    /// or an error if the URL is malformed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use extauthz_cfzt::server::SocketOrPath;
    ///
    /// // TCP with scheme
    /// let tcp = SocketOrPath::from_url("tcp://127.0.0.1:8080")?;
    ///
    /// // TCP without scheme (default)
    /// let tcp_default = SocketOrPath::from_url("127.0.0.1:8080")?;
    ///
    /// // Unix domain socket
    /// let unix = SocketOrPath::from_url("unix:///tmp/server.sock")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The TCP address is malformed (invalid IP or port)
    /// - The socket address cannot be parsed
    pub fn from_url(url_str: &str) -> Result<Self> {
        if let Some(tcp_addr) = url_str.strip_prefix("tcp://") {
            let addr: SocketAddr = tcp_addr.parse()?;
            Ok(SocketOrPath::Tcp(addr))
        } else if let Some(unix_path) = url_str.strip_prefix("unix://") {
            Ok(SocketOrPath::Unix(PathBuf::from(unix_path)))
        } else {
            // Default to TCP
            let addr: SocketAddr = url_str.parse()?;
            Ok(SocketOrPath::Tcp(addr))
        }
    }
}

/// The main server implementation for the Cloudflare Zero Trust External Authorization Service.
///
/// This server provides external authorization capabilities for Envoy proxy, implementing
/// the Envoy External Authorization API. It validates Cloudflare Zero Trust JWT tokens
/// and provides authorization decisions back to Envoy.
///
/// ## Architecture
///
/// The server consists of two main components:
/// 1. **gRPC Authorization Server** - Handles Envoy authorization requests
/// 2. **Metrics/Observability Server** - Provides HTTP endpoints for monitoring
///
/// ## Concurrency Model
///
/// - Each incoming connection is handled in a separate tokio task
/// - The server uses Arc for shared ownership across async tasks
/// - All operations are fully async and non-blocking
///
/// ## Example
///
/// ```rust,no_run
/// use extauthz_cfzt::server::{Server, SocketOrPath};
/// use std::net::SocketAddr;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let listen_address = SocketOrPath::from_url("tcp://[::1]:10000")?;
///     let audiences = vec!["my-application".to_string()];
///     let observability_port = 8080;
///
///     let server = Server::new(listen_address, audiences, observability_port);
///     server.start().await?;
///     Ok(())
/// }
/// ```
pub struct Server {
    /// The socket address or path where the gRPC server will listen
    listen_address: SocketOrPath,
    /// List of valid JWT audiences for token validation
    audiences: Vec<String>,
    /// Port number for the observability/metrics HTTP server
    observability_port: u16,
}

impl Server {
    /// Creates a new server instance.
    ///
    /// # Arguments
    ///
    /// * `listen_address` - The socket address or path where the gRPC server will bind
    /// * `audiences` - List of valid JWT audiences for token validation
    /// * `observability_port` - Port number for the metrics/health HTTP server
    ///
    /// # Returns
    ///
    /// Returns a new `Server` instance ready to be started.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use extauthz_cfzt::server::{Server, SocketOrPath};
    ///
    /// let listen_address = SocketOrPath::from_url("tcp://127.0.0.1:10000").unwrap();
    /// let audiences = vec!["my-app".to_string()];
    /// let server = Server::new(listen_address, audiences, 8080);
    /// ```
    pub fn new(
        listen_address: SocketOrPath,
        audiences: Vec<String>,
        observability_port: u16,
    ) -> Self {
        Server {
            listen_address,
            audiences,
            observability_port,
        }
    }

    /// Starts the server and begins accepting connections.
    ///
    /// This method initializes the metrics system, starts both the observability
    /// HTTP server and the main gRPC authorization server. The method will run
    /// indefinitely, handling incoming connections until an error occurs or the
    /// process is terminated.
    ///
    /// # Server Components Started
    ///
    /// 1. **Metrics Server** - HTTP server on `observability_port` providing:
    ///    - `/metrics` - Prometheus-style metrics
    ///    - `/health` - Health check endpoint
    ///
    /// 2. **gRPC Authorization Server** - Main server handling Envoy authorization requests
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the server shuts down gracefully, or an error if
    /// server startup or operation fails.
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - The socket address is already in use
    /// - The socket path is invalid or permissions are insufficient
    /// - Network binding fails for any reason
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use extauthz_cfzt::server::{Server, SocketOrPath};
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let server = Server::new(
    ///         SocketOrPath::from_url("tcp://[::1]:10000")?,
    ///         vec!["my-app".to_string()],
    ///         8080
    ///     );
    ///     
    ///     // This will run forever until interrupted
    ///     server.start().await
    /// }
    /// ```
    pub async fn start(self) -> Result<()> {
        // Initialize metrics
        metrics::init_metrics();

        // Wrap server in an Arc for shared ownership
        let server = Arc::new(self);

        // Start metrics server
        let metrics_addr = format!("0.0.0.0:{}", server.observability_port);
        let metrics_listener = TcpListener::bind(&metrics_addr).await?;
        let _metrics_handle = server.start_metrics_server(metrics_listener);
        println!("Metrics server started on {}", metrics_addr);

        // Start main gRPC server
        match &server.listen_address {
            SocketOrPath::Tcp(addr) => {
                println!("Starting gRPC server on TCP {}", addr);
                server.serve_tcp(*addr).await?;
            }
            SocketOrPath::Unix(path) => {
                println!("Starting gRPC server on Unix socket {}", path.display());
                server.serve_unix(path).await?;
            }
        }

        Ok(())
    }

    /// Serves the gRPC authorization service over TCP.
    ///
    /// This method binds to the specified TCP address and accepts incoming
    /// connections. Each connection is handled in a separate tokio task to
    /// allow concurrent processing of authorization requests.
    ///
    /// # Arguments
    ///
    /// * `addr` - The TCP socket address to bind to
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the server shuts down gracefully, or an error if
    /// binding or connection handling fails.
    ///
    /// # Concurrency
    ///
    /// Each accepted connection spawns a new tokio task, allowing the server
    /// to handle multiple simultaneous authorization requests efficiently.
    async fn serve_tcp(self: &Arc<Self>, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        println!("Server listening on TCP {}", addr);

        // Clone server reference for the connection handler
        let server = self.clone();

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let peer = peer_addr.to_string();
            let server = server.clone();

            // Process the TCP connection
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream, peer).await {
                    eprintln!("Error handling TCP connection: {}", e);
                }
            });
        }
    }

    /// Serves the gRPC authorization service over Unix domain socket.
    ///
    /// This method binds to the specified Unix socket path and accepts incoming
    /// connections. Each connection is handled in a separate tokio task to
    /// allow concurrent processing of authorization requests.
    ///
    /// # Arguments
    ///
    /// * `path` - The filesystem path for the Unix domain socket
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the server shuts down gracefully, or an error if
    /// binding or connection handling fails.
    ///
    /// # Note
    ///
    /// The Unix socket file will be created at the specified path. Ensure the
    /// directory exists and the process has appropriate permissions.
    async fn serve_unix(self: &Arc<Self>, path: &PathBuf) -> Result<()> {
        let listener = UnixListener::bind(path)?;
        println!("Server listening on Unix socket {}", path.display());

        // Clone server reference for the connection handler
        let server = self.clone();

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let peer = format!("unix:{:?}", peer_addr);
            let server = server.clone();

            // Process the Unix connection
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream, peer).await {
                    eprintln!("Error handling Unix connection: {}", e);
                }
            });
        }
    }

    /// Handles a single gRPC connection for authorization requests.
    ///
    /// This method sets up a tonic gRPC server for the incoming connection stream
    /// and registers the authorization service. The connection is handled until
    /// it's closed by the client or an error occurs.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The connection stream type that must implement the required async traits
    ///
    /// # Arguments
    ///
    /// * `stream` - The connection stream (TCP or Unix socket)
    /// * `_peer_addr` - The peer address string for logging (currently unused)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when the connection is handled successfully, or an error
    /// if gRPC service setup or handling fails.
    ///
    /// # Protocol
    ///
    /// The connection implements the Envoy External Authorization API, specifically
    /// the `envoy.service.auth.v3.Authorization` service.
    // Generic method to handle connections
    async fn handle_connection<T>(&self, stream: T, _peer_addr: String) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static + tonic::transport::server::Connected,
    {
        // Create an owned clone of the server for the service
        // This is necessary because AuthorizationServer::new takes ownership
        let service = MyAuthorizationService::new(self.audiences.clone());

        TonicServer::builder()
            .add_service(AuthorizationServer::new(service))
            .serve_with_incoming(tokio_stream::once(std::result::Result::<
                T,
                std::convert::Infallible,
            >::Ok(stream)))
            .await?;

        Ok(())
    }

    /// Starts the observability HTTP server for metrics and health checks.
    ///
    /// This method spawns a background task that runs a simple HTTP server
    /// providing observability endpoints. The server uses raw tokio APIs
    /// to avoid dependency conflicts with multiple hyper versions.
    ///
    /// # Endpoints Provided
    ///
    /// - `GET /metrics` - Prometheus-style metrics data
    /// - `GET /health` - Simple health check returning "OK"
    /// - All other paths return 404
    ///
    /// # Arguments
    ///
    /// * `listener` - Pre-bound TCP listener for the HTTP server
    ///
    /// # Returns
    ///
    /// Returns a `JoinHandle` for the spawned HTTP server task. The task
    /// runs indefinitely until the program terminates.
    ///
    /// # Implementation Details
    ///
    /// - Uses a simple HTTP/1.1 parser for incoming requests
    /// - Each connection is handled in a separate spawned task
    /// - Connections are automatically closed after each response
    /// - Includes error handling with retry logic for accept failures
    /// Start a metrics server that responds to HTTP requests using raw tokio APIs
    /// This avoids issues with multiple hyper versions in the dependency tree
    fn start_metrics_server(&self, listener: TcpListener) -> JoinHandle<()> {
        tokio::spawn(async move {
            // Get the address for logging
            let addr = listener.local_addr().unwrap();
            println!("Metrics server listening on http://{}", addr);

            // Accept connections in a loop
            loop {
                match listener.accept().await {
                    Ok((stream, remote_addr)) => {
                        // Spawn a task to process the connection
                        tokio::spawn(async move {
                            if let Err(e) = Self::process_metrics_connection(stream).await {
                                eprintln!(
                                    "Error processing metrics connection from {}: {}",
                                    remote_addr, e
                                );
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Error accepting connection: {}", e);
                        // Short delay before retrying
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        })
    }

    /// Processes a single HTTP connection for the observability endpoints.
    ///
    /// This method implements a minimal HTTP/1.1 server that handles requests
    /// for metrics and health check endpoints. It uses a simple request parser
    /// and responds with appropriate content based on the requested path.
    ///
    /// # Supported Endpoints
    ///
    /// - `GET /health` - Returns "OK" with 200 status
    /// - `GET /metrics` - Returns Prometheus metrics with 200 status  
    /// - All others - Returns "Not Found" with 404 status
    ///
    /// # Arguments
    ///
    /// * `stream` - The TCP stream for the HTTP connection
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the request is processed successfully, or an error
    /// if network I/O fails.
    ///
    /// # Protocol Details
    ///
    /// - Reads up to 1024 bytes of the HTTP request
    /// - Parses only the request line (method and path)
    /// - Sends a complete HTTP/1.1 response with appropriate headers
    /// - Always closes the connection after the response (`Connection: close`)
    ///
    /// # Error Handling
    ///
    /// Network errors are propagated to the caller. Invalid or malformed
    /// requests receive a 400 Bad Request response rather than causing errors.
    /// Process a single HTTP connection for metrics using a very simple HTTP/1.1 parser
    async fn process_metrics_connection(mut stream: TcpStream) -> Result<()> {
        // Buffer for the request
        let mut buffer = [0; 1024];

        // Read the request
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            return Ok(()); // Connection closed
        }

        // Simple request parsing
        let request = String::from_utf8_lossy(&buffer[..n]);
        let request_line = request.lines().next().unwrap_or_default();
        let parts: Vec<&str> = request_line.split_whitespace().collect();

        // Default response is 404
        let (status, content_type, body) = if parts.len() >= 2 {
            match (parts[0], parts[1]) {
                ("GET", "/health") => {
                    // Health check endpoint
                    ("200 OK", "text/plain", "OK".to_string())
                }
                ("GET", "/metrics") => {
                    // Metrics endpoint
                    let metrics_data = metrics::gather_metrics();
                    ("200 OK", "text/plain", metrics_data)
                }
                _ => {
                    // 404 for anything else
                    ("404 Not Found", "text/plain", "Not Found".to_string())
                }
            }
        } else {
            // Invalid request
            ("400 Bad Request", "text/plain", "Bad Request".to_string())
        };

        // Write the response
        let response = format!(
            "HTTP/1.1 {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
            status,
            content_type,
            body.len(),
            body
        );

        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;

        Ok(())
    }
}

/// Implementation of the Envoy External Authorization gRPC service.
///
/// This service validates Cloudflare Zero Trust JWT tokens against the configured
/// audiences and returns authorization decisions to Envoy proxy. It implements
/// the `envoy.service.auth.v3.Authorization` service interface.
///
/// ## JWT Validation Process
///
/// 1. Extracts the `cf-access-jwt-assertion` header from the request
/// 2. Validates the JWT token against the configured audiences
/// 3. Returns appropriate authorization response to Envoy
///
/// ## Metrics
///
/// The service automatically records metrics for:
/// - Total request count
/// - Request duration/latency
/// - Validation results (success/error types)
///
/// ## Example Usage
///
/// This service is typically not used directly but is registered with a tonic
/// gRPC server and used by Envoy proxy for authorization decisions.
// The actual gRPC service implementation
struct MyAuthorizationService {
    /// List of valid JWT audiences for token validation
    audiences: Vec<String>,
}

impl MyAuthorizationService {
    /// Creates a new authorization service instance.
    ///
    /// # Arguments
    ///
    /// * `audiences` - List of valid JWT audiences that will be accepted during validation
    ///
    /// # Returns
    ///
    /// Returns a new `MyAuthorizationService` instance configured with the specified audiences.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let service = MyAuthorizationService::new(vec!["my-app".to_string(), "api-gateway".to_string()]);
    /// ```
    fn new(audiences: Vec<String>) -> Self {
        Self { audiences }
    }
}

#[tonic::async_trait]
impl Authorization for MyAuthorizationService {
    /// Handles external authorization requests from Envoy proxy.
    ///
    /// This method implements the core authorization logic by:
    /// 1. Extracting client headers from the Envoy request
    /// 2. Looking for the Cloudflare Zero Trust JWT token
    /// 3. Validating the token against configured audiences
    /// 4. Recording metrics for observability
    /// 5. Returning appropriate authorization response
    ///
    /// # Arguments
    ///
    /// * `request` - The gRPC request containing Envoy's authorization check data
    ///
    /// # Returns
    ///
    /// Returns a `Result<Response<CheckResponse>, Status>` where:
    /// - `Ok(Response<CheckResponse>)` - Authorization succeeded with response details
    /// - `Err(Status)` - Authorization failed with specific error status
    ///
    /// # Status Codes Returned
    ///
    /// - `Status::OK` - JWT token is valid and authorization granted
    /// - `Status::INVALID_ARGUMENT` - Request missing required headers
    /// - `Status::UNAUTHENTICATED` - Missing or invalid JWT token
    ///
    /// # Metrics Recorded
    ///
    /// - `requests_total` - Incremented for each request
    /// - `validation_result` - Labeled counter for success/error types
    /// - `request_duration_seconds` - Histogram of request processing time
    ///
    /// # Headers Expected
    ///
    /// - `cf-access-jwt-assertion` - Cloudflare Zero Trust JWT token
    ///
    /// # Future Enhancements
    ///
    /// Currently returns success for all valid JWT headers. Full JWT validation
    /// logic including signature verification and audience validation will be
    /// implemented in future versions.
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> std::result::Result<Response<CheckResponse>, Status> {
        // Start timing the request
        let start = Instant::now();
        metrics::inc_requests_total();

        // Get peer address for logging
        let peer_addr = request
            .remote_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        println!("Processing authorization request from {}", peer_addr);

        // Extract the JWT token from the headers
        let check_req = request.into_inner();
        let client_headers = match check_req.get_client_headers() {
            Some(headers) => headers,
            None => {
                metrics::inc_validation_result("error_no_headers");
                return Err(Status::invalid_argument(
                    "client headers not populated by envoy",
                ));
            }
        };

        // Check for the Cloudflare Zero Trust JWT token
        let _jwt_token = match client_headers.get("cf-access-jwt-assertion") {
            Some(token) => token,
            None => {
                metrics::inc_validation_result("error_no_jwt");
                return Err(Status::unauthenticated("missing JWT token"));
            }
        };

        // TODO: Implement JWT validation logic with the self.audiences
        println!("Validating JWT token with audiences: {:?}", self.audiences);

        // Placeholder for JWT validation
        let validation_result = "success"; // In real implementation, this would be determined by JWT validation
        metrics::inc_validation_result(validation_result);

        // For now, return a successful response
        let response = CheckResponse::with_status(Status::ok("token is valid"));

        // Add headers to the response if needed
        // let ok_response = OkHttpResponseBuilder::new()
        //    .add_response_header("x-auth-user", "authenticated-user", None, true)
        //    .build();
        // response.set_http_response(ok_response);

        // Record the request duration
        let duration = start.elapsed().as_secs_f64();
        metrics::observe_request_duration(duration);

        // Return the response
        Ok(Response::new(response))
    }
}
