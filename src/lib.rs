pub mod error;
pub mod health_server;
pub mod metrics;
pub mod request;
pub mod response;
pub mod schema;
pub mod server;
pub mod signal;
pub mod validation;
pub mod validator;

use envoy_types::ext_authz::v3::pb::{Authorization, AuthorizationServer};
use tonic::transport::server::Router;
use tonic::transport::Server;

/// Creates a new router for the given authorization server
pub fn new_router(server: impl Authorization) -> Router {
    Server::builder().add_service(AuthorizationServer::new(server))
}
