use envoy_types::ext_authz::v3::pb::{Authorization, AuthorizationServer};
use std::process::ExitCode;
use tonic::transport::server::Router;
use tonic::transport::Server;
use anyhow::Error;

pub fn handle_error<E: std::fmt::Display>(error: E, message: &str, code: u8) -> ExitCode {
    log::error!("{}: {}", message, error);
    ExitCode::from(code)
}

pub fn new_router(server: impl Authorization) -> Router {
    Server::builder().add_service(AuthorizationServer::new(server))
}
