mod socket;

use std::net::{TcpListener, SocketAddr};
use url::Url;

#[cfg(unix)]
use std::os::unix::net::UnixListener;

pub use socket::{run_server, EmptyResult};

pub enum Listener {
    Unix(UnixListener),
    Tcp(TcpListener),
}

#[derive(Debug)]
pub enum ListenerError {
    InvalidScheme(String),
    UrlParseError(url::ParseError),
    IoError(std::io::Error),
    #[cfg(not(unix))]
    UnixUnsupported,
}

impl From<url::ParseError> for ListenerError {
    fn from(err: url::ParseError) -> Self {
        ListenerError::UrlParseError(err)
    }
}

impl From<std::io::Error> for ListenerError {
    fn from(err: std::io::Error) -> Self {
        ListenerError::IoError(err)
    }
}

impl Listener {
    pub fn from_url(url: Url) -> Result<Self, ListenerError> {
        match url.scheme() {
            "unix" => Self::from_unix_url(url),
            "tcp" => Self::from_tcp_url(url),
            scheme => Err(ListenerError::InvalidScheme(scheme.to_string())),
        }
    }

    #[cfg(unix)]
    fn from_unix_url(url: Url) -> Result<Self, ListenerError> {
        let path = url.path();
        let listener = UnixListener::bind(path)?;
        Ok(Listener::Unix(listener))
    }

    #[cfg(not(unix))]
    fn from_unix_url(_url: Url) -> Result<Self, ListenerError> {
        Err(ListenerError::UnixUnsupported)
    }

    fn from_tcp_url(url: Url) -> Result<Self, ListenerError> {
        let host = url.host_str().unwrap_or("0.0.0.0");
        let port = url.port().unwrap_or(80);
        let addr = format!("{}:{}", host, port);
        let socket_addr: SocketAddr = addr.parse()
            .map_err(|_| ListenerError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid socket address: {}", addr)
            )))?;

        let listener = TcpListener::bind(socket_addr)?;
        Ok(Listener::Tcp(listener))
    }
}