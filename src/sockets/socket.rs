use std::net::TcpListener;
use tokio::net::{TcpListener as TokioTcpListener, UnixListener as TokioUnixListener};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::server::Router;

use super::Listener;

#[cfg(unix)]
use std::os::unix::net::UnixListener;
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;

#[cfg(not(unix))]
type UnixListener = ();
#[cfg(not(unix))]
type UnixListenerStream = ();

use anyhow::Result;

pub type EmptyResult = Result<()>;

#[cfg(unix)]
fn bind_unix_socket(listener: UnixListener) -> Result<UnixListenerStream, std::io::Error> {
    Ok(UnixListenerStream::new(TokioUnixListener::from_std(
        listener,
    )?))
}

#[cfg(not(unix))]
fn bind_unix_socket(_listener: UnixListener) -> Result<UnixListenerStream, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Unix sockets not supported on this platform",
    ))
}

fn bind_tcp_socket(listener: TcpListener) -> Result<TcpListenerStream, std::io::Error> {
    Ok(TcpListenerStream::new(TokioTcpListener::from_std(
        listener,
    )?))
}

fn handle_result(result: Result<(), tonic::transport::Error>) -> EmptyResult {
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
}

pub async fn run_server(router: Router, listener: Listener) -> EmptyResult {
    match listener {
        #[cfg(unix)]
        Listener::Unix(socket) => {
            handle_result(router.serve_with_incoming(bind_unix_socket(socket)?).await)
        }
        #[cfg(not(unix))]
        Listener::Unix(_) => {
            Err("Unix sockets not supported on this platform".into())
        }
        Listener::Tcp(socket) => {
            handle_result(router.serve_with_incoming(bind_tcp_socket(socket)?).await)
        }
    }
}