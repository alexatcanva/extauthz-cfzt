mod config;
mod health;
mod helpers;
mod server;
mod socket;
mod sockets;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use config::audience::schema::AudienceProvider;
use config::bootstrap::schema::{Configuration as BootstrapConfiguration, TimeConstraintMode};
use health::{run_health_server, HealthState};
use helpers::new_router;
use server::extauthz::CloudflareZeroTrustAuthorizationServer;
// Using our custom socket implementation instead
use sockets::run_server;
use std::{process::ExitCode, str::FromStr, sync::Arc};
use tokio::runtime::Builder;
use tokio_cron_scheduler::{Job, JobScheduler};

type ExitResult<T> = std::result::Result<T, ExitCode>;

/// Cloudflare Zero Trust External Authorization Service for Envoy
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Socket address to listen on (e.g., "tcp://[::1]:10000")
    #[arg(long, env = "LISTENER", default_value = "tcp://[::1]:10000")]
    listener: String,

    /// Required Cloudflare team name
    #[arg(long, env = "TEAM_NAME")]
    team_name: String,

    /// Static JWT verification keys (optional)
    #[arg(long, env = "STATIC_KEYS", default_value = "")]
    static_keys: String,

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

    /// Single audience value for validation
    #[arg(long, env = "AUDIENCE", default_value = "")]
    audience: String,

    /// Comma-separated list of audiences for validation
    #[arg(long, env = "AUDIENCES", default_value = "")]
    audiences: String,

    /// Health server address
    #[arg(long, env = "HEALTH_ADDRESS", default_value = "0.0.0.0:8080")]
    health_address: String,
}

#[cfg(all(target_env = "musl", target_pointer_width = "64"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc; // Use mimalloc allocator for Muslc targets

fn main() -> ExitCode {
    env_logger::init();
    log::info!("Starting runtime");

    let cli = Cli::parse();
    if let Err(e) = start(cli) {
        return e;
    }

    ExitCode::from(0)
}

fn create_bootstrap_configuration(cli: &Cli) -> Result<BootstrapConfiguration> {
    let static_keys = if !cli.static_keys.is_empty() {
        // Use anyhow to wrap the error
        Some(
            rust_cfzt_validator::api::TeamKeys::from_str(&cli.team_name, &cli.static_keys)
                .map_err(|e| anyhow!("Failed to parse team keys: {}", e))?,
        )
    } else {
        None
    };

    Ok(BootstrapConfiguration::new_single_team_configuration(
        &cli.listener,
        &cli.team_name,
        static_keys,
        &cli.sync_schedule,
        &cli.nbf_validation,
        &cli.exp_validation,
    ))
}

fn create_audience_provider(cli: &Cli) -> Result<Box<dyn AudienceProvider>> {
    use config::audience::schema::StaticAudienceProvider;

    match cli.audience_provider.to_lowercase().as_str() {
        "static" => {
            // Try to use single audience first
            if !cli.audience.is_empty() {
                return Ok(Box::new(StaticAudienceProvider::new_single_aud(
                    &cli.audience,
                )));
            }

            // Then try multiple audiences
            if !cli.audiences.is_empty() {
                let audiences: Vec<String> = cli.audiences.split(',').map(String::from).collect();
                return Ok(Box::new(StaticAudienceProvider::new(audiences)));
            }

            Err(anyhow!("No audience configured for static provider"))
        }
        _ => Err(anyhow!("Invalid audience provider")),
    }
}

fn start(cli: Cli) -> ExitResult<()> {
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| helpers::handle_error(e, "error during runtime start", 1))?;

    log::info!("Creating bootstrap configuration");
    let configuration = create_bootstrap_configuration(&cli)
        .with_context(|| "error during config creation")
        .map_err(|e| helpers::handle_error(e, "error during config creation", 2))?;

    log::info!("Creating audience provider");
    let aud_provider = Arc::new(
        create_audience_provider(&cli)
            .with_context(|| "error during audience provider creation")
            .map_err(|e| helpers::handle_error(e, "error during audience provider creation", 3))?,
    );

    runtime
        .block_on(async_main(configuration, aud_provider, &cli.health_address))
        .with_context(|| "error during execution")
        .map_err(|e| helpers::handle_error(e, "error during execution", 100))
}

async fn async_main(
    bootstrap: BootstrapConfiguration,
    aud_provider: Arc<Box<dyn AudienceProvider>>,
    health_address: &str,
) -> Result<()> {
    // Initialize health state
    let health_state = Arc::new(HealthState::new());

    // Start health server
    let health_state_clone = Arc::clone(&health_state);
    let health_addr = health_address.to_string(); // Clone the string to avoid lifetime issues
    tokio::spawn(async move {
        if let Err(e) = run_health_server(health_state_clone, &health_addr).await {
            log::error!("Health server error: {}", e);
        }
    });
    let listener = bootstrap.open_listener()?;
    let validator = Arc::new(bootstrap.new_validator()?);
    let mut scheduler = JobScheduler::new().await?;

    let router = new_router(CloudflareZeroTrustAuthorizationServer::new(
        validator.clone(),
        aud_provider,
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
