use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{anyhow, Ok, Result};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, UnixListener},
    sync::mpsc,
    task::JoinHandle,
};
use tonic::{
    transport::Server as TonicServer,
    Request, Response, Status,
};
// Only import the basic types we need
use hyper::{Method, StatusCode};
use hyper::header::HeaderValue;

// Use existing envoy-types crate - it has the external auth protobuf definitions
use envoy_types::ext_authz::v3::{CheckRequestExt, CheckResponseExt};
use envoy_types::ext_authz::v3::pb::{
    Authorization, AuthorizationServer, CheckRequest, CheckResponse,
};
use crate::metrics;

/// Socket address that can be either TCP or Unix
pub enum SocketOrPath {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl SocketOrPath {
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

/// The server struct holds the main server implementation for the
/// Cloudflare Zero Trust External Authorization Service.
pub struct Server {
    listen_address: SocketOrPath,
    audiences: Vec<String>,
    observability_port: u16,
}

impl Server {
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

    pub async fn start(self) -> Result<()> {
        // Initialize metrics
        metrics::init_metrics();
        
        // Wrap server in an Arc for shared ownership
        let server = Arc::new(self);
        
        // Set up shutdown channels (unused for now but could be used to implement graceful shutdown)
        let (_tx, _rx) = mpsc::channel::<()>(1);
        
        // Start observability server (metrics, health checks, etc.)
        let observability_addr = format!("0.0.0.0:{}", server.observability_port);
        let observability_listener = TcpListener::bind(&observability_addr).await?;
        let observability_handle = Self::start_metrics_server(observability_listener);
        
        println!("Metrics server listening on {}", observability_addr);
        
        // Handle main gRPC service
        let grpc_handle = tokio::spawn(async move {
            match &server.listen_address {
                SocketOrPath::Tcp(addr) => {
                    println!("Starting gRPC server on TCP {}", addr);
                    server.serve_tcp(*addr).await
                },
                SocketOrPath::Unix(path) => {
                    println!("Starting gRPC server on Unix socket {}", path.display());
                    server.serve_unix(path).await
                },
            }
        });
        
        // Wait for both tasks to complete
        tokio::select! {
            res = grpc_handle => {
                match res {
                    std::result::Result::Ok(inner_res) => inner_res?,
                    std::result::Result::Err(e) => return Err(anyhow::anyhow!("gRPC server task failed: {}", e)),
                }
            },
            _ = observability_handle => {
                return Err(anyhow::anyhow!("Metrics server unexpectedly stopped"));
            }
        }
        
        Ok(())
    }

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

    // Static method to handle connections
    async fn handle_connection<T>(
        &self,
        stream: T,
        peer_addr: String,
    ) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static + tonic::transport::server::Connected,
    {
        // Create an owned clone of the server for the service
        // This is necessary because AuthorizationServer::new takes ownership
        let owned_server = Server {
            listen_address: match &self.listen_address {
                SocketOrPath::Tcp(addr) => SocketOrPath::Tcp(*addr),
                SocketOrPath::Unix(path) => SocketOrPath::Unix(path.clone()),
            },
            audiences: self.audiences.clone(),
            observability_port: self.observability_port,
        };
        
        // Create a service instance from this server's implementation
        let svc = AuthorizationServer::new(owned_server);
        
        TonicServer::builder()
            .add_service(svc)
            .serve_with_incoming(tokio_stream::once(Ok(stream)))
            .await?;

        // Handle the connection with your service
        // For example with tonic/grpc:
        // let svc = YourServiceImpl::new(audiences);
        // Server::builder().add_service(svc).serve_with_incoming(tokio_stream::once(Ok(stream))).await?;

        println!("Accepted connection from {}", peer_addr);
        println!("Using audiences: {:?}", self.audiences);
        // TODO: Implement your connection handling logic

        Ok(())
    }

// Implement the gRPC Authorization service trait
#[tonic::async_trait]
impl Authorization for Server {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> std::result::Result<Response<CheckResponse>, Status> {
        // Start timing the request
        let start = std::time::Instant::now();
        metrics::inc_requests_total();
        
        // Get peer address for logging
        let peer_addr = request.remote_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());
            
        println!("Processing authorization request from {}", peer_addr);
        
        // Extract the JWT token from the headers
        let check_req = request.into_inner();
        let client_headers = match check_req.get_client_headers() {
            Some(headers) => headers,
            None => {
                metrics::inc_validation_result("error_no_headers");
                return Err(Status::invalid_argument("client headers not populated by envoy"));
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
        
        // Convert Result<Response<T>, anyhow::Error> to Result<Response<T>, tonic::Status>
        std::result::Result::<_, Status>::Ok(Response::new(response))
    }
}

// Generate tonic gRPC service for our server
impl Server {
    pub fn into_service(self) -> AuthorizationServer<Server> {
        AuthorizationServer::new(self)
    }
    
    /// Start a metrics server that responds to HTTP requests using raw tokio APIs
    /// This avoids issues with multiple hyper versions in the dependency tree
    fn start_metrics_server(listener: TcpListener) -> JoinHandle<()> {
        tokio::spawn(async move {
            // Get the address for logging
            let addr = listener.local_addr().unwrap();
            println!("Metrics server listening on http://{}", addr);
            
            // Accept connections in a loop
            loop {
                match listener.accept().await {
                    std::result::Result::Ok((stream, remote_addr)) => {
                        // Spawn a task to process the connection
                        tokio::spawn(async move {
                            if let std::result::Result::Err(e) = Self::process_metrics_connection(stream).await {
                                eprintln!("Error processing metrics connection from {}: {}", remote_addr, e);
                            }
                        });
                    },
                    std::result::Result::Err(e) => {
                        eprintln!("Error accepting connection: {}", e);
                        // Short delay before retrying
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        })
    }
    
    /// Process a single HTTP connection for metrics using a very simple HTTP/1.1 parser
    async fn process_metrics_connection(mut stream: TcpStream) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
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
                    ("200 OK", "text/plain", "OK")
                },
                ("GET", "/metrics") => {
                    // Metrics endpoint
                    let metrics_data = metrics::gather_metrics();
                    ("200 OK", "text/plain", metrics_data)
                },
                _ => {
                    // 404 for anything else
                    ("404 Not Found", "text/plain", "Not Found")
                }
            }
        } else {
            // Invalid request
            ("400 Bad Request", "text/plain", "Bad Request")
        };
        
        // Write the response
        let response = format!(
            "HTTP/1.1 {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            status, content_type, body.len(), body
        );
        
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;
        
        Ok(())
    }
    }
}
