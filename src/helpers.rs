use envoy_types::ext_authz::v3::pb::{Authorization, AuthorizationServer};
use tonic::transport::server::Router;
use tonic::transport::Server;

pub fn new_router(server: impl Authorization) -> Router {
    Server::builder().add_service(AuthorizationServer::new(server))
}
