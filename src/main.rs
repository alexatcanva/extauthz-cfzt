mod config;
mod health;
mod helpers;
mod server;
mod sockets;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use config::bootstrap::schema::{Configuration as BootstrapConfiguration, TimeConstraintMode};
use health::{run_health_server, HealthState};
use helpers::new_router;
use rust_cfzt_validator::api::TeamKeys;
use server::extauthz::CloudflareZeroTrustAuthorizationServer;

// TODO: remove this run_server
use sockets::run_server;
use std::sync::Arc;
use tokio_cron_scheduler::{Job, JobScheduler};

/// Cloudflare Zero Trust External Authorization Service for Envoy
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Socket address to listen on:
    /// - For TCP: "tcp://[::1]:10000" or "tcp://127.0.0.1:10000"
    /// - For Unix: "unix:///tmp/extauthz.sock"
    #[arg(long, env = "LISTENER", default_value = "tcp://[::1]:10000")]
    listener: String,

    /// Required Cloudflare team name
    #[arg(long, env = "TEAM_NAME")]
    team_name: String,

    /// Static JWT verification keys (optional)
    #[arg(long, env = "STATIC_KEYS", default_value = "")]
    static_keys: Option<String>,

    /// Not Before (NBF) validation mode: strict or lax
    #[arg(long, env = "NBF_VALIDATION", default_value = "strict")]
    nbf_validation: TimeConstraintMode,

    /// Expiration validation mode: strict or lax
    #[arg(long, env = "EXP_VALIDATION", default_value = "strict")]
    exp_validation: TimeConstraintMode,

    /// Cron schedule for key synchronization
    #[arg(long, env = "SYNC_SCHEDULE", default_value = "0 0 0 * * *")]
    sync_schedule: String,

    /// Provider type for audience validation
    #[arg(long, env = "AUDIENCE_PROVIDER", default_value = "static")]
    audience_provider: String,

    /// A list of audiences to validate against
    #[arg(long, env = "AUDIENCE", default_value = "")]
    audience: Vec<String>,

    /// Observability port for metrics and health checks.
    #[arg(long, env = "OBSERVABILITY_PORT", default_value = "8083")]
    observability_port: u16,
}

#[cfg(all(target_env = "musl", target_pointer_width = "64"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc; // Use mimalloc allocator for Muslc targets

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    log::info!("Starting Cloudflare Zero Trust External Authorization Service");

    let cli = Cli::parse();

    log::info!("Creating bootstrap configuration");

    // Retrieve static keys if provided
    // TODO: This is super ugly. Refactor to use a better approach.
    let keys = if let Some(static_keys) = &cli.static_keys {
        Some(
            TeamKeys::from_str(&cli.team_name, static_keys)
                .map_err(|e| anyhow!("error retrieving static keys: {}", e))?,
        )
    } else {
        None
    };

    // Create the bootstrap configuration
    let configuration = BootstrapConfiguration::new_single_team_configuration(
        &cli.listener,
        &cli.team_name,
        keys,
        &cli.sync_schedule,
        &cli.nbf_validation,
        &cli.exp_validation,
    );

    run(configuration, cli.audience, cli.observability_port)
        .await
        .with_context(|| "error running server")
}

async fn run(
    bootstrap: BootstrapConfiguration,
    aud_provider: Vec<String>,
    observability_port: u16,
) -> Result<()> {
    // Initialize health state
    let health_state = Arc::new(HealthState::new());

    // Start health server
    let health_state_clone = Arc::clone(&health_state);
    tokio::spawn(async move {
        if let Err(e) = run_health_server(health_state_clone, observability_port).await {
            log::error!("Health server error: {}", e);
        }
    });
    let listener = bootstrap.open_listener()?;
    let validator = Arc::new(bootstrap.new_validator()?);
    let mut scheduler = JobScheduler::new().await?;

    let router = new_router(CloudflareZeroTrustAuthorizationServer::new(
        validator.clone(),
        Arc::new(aud_provider),
        &bootstrap.validator.get_default_team_name(),
        bootstrap.nbf_validation,
        bootstrap.exp_validation,
    ));

    // Run initial sync if needed
    let health_state_clone = Arc::clone(&health_state);
    if bootstrap.validator.requires_refresh() {
        log::info!("Running initial validator synchronization");
        if validator.sync().is_ok() {
            log::info!("Initial validator synchronization successful");
            health_state_clone.mark_validator_ready();
        } else {
            log::error!("Initial validator synchronization failed");
            // Don't mark ready - will retry with scheduler
        }

        log::info!("Registering validator synchronization job");
        let validator_clone = validator.clone();
        let health_state_job = health_state_clone.clone();

        let sync_job = Job::new(bootstrap.sync_schedule, move |_, _| {
            log::info!("Triggering validator synchronization");
            match validator_clone.sync() {
                Ok(_) => {
                    log::info!("Validator synchronization successful");
                    health_state_job.mark_validator_ready();
                }
                Err(e) => {
                    log::error!("Validator synchronization failed: {}", e);
                    // Don't change ready state on error
                }
            }
        })?;

        scheduler.add(sync_job).await?;
    } else {
        // If no refresh is required, we're immediately ready
        health_state_clone.mark_validator_ready();
    }

    log::info!("Starting validation synchronization job");
    scheduler.start().await?;

    log::info!("Running ExtAuthz server");
    run_server(router, listener).await?;

    log::info!("Server stopped, shutting down validation synchronization job");
    scheduler.shutdown().await?;

    Ok(())
}
