use crate::sockets::{Listener, EmptyResult};
use tonic::transport::server::Router;

pub async fn run_server(router: Router, listener: Listener) -> EmptyResult {
    crate::sockets::run_server(router, listener).await
}
