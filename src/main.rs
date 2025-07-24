use anyhow::Result;
use clap::Parser;
use extauthz_cfzt::{
    error::AppResult,
    health_server::{run_health_server, HealthState},
    metrics,
    schema::{
        Configuration, StaticTeamValidatorConfiguration, TimeConstraintMode, ValidatorConfiguration,
    },
    validation::CloudflareZeroTrustAuthorizationServer,
};
use rust_cfzt_validator::api::TeamKeys;
use std::sync::Arc;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

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

    /// Log level
    #[arg(long, env = "LOG_LEVEL", default_value = "info")]
    log_level: Level,
}

#[cfg(all(target_env = "musl", target_pointer_width = "64"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc; // Use mimalloc allocator for Muslc targets

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(cli.log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global default subscriber");

    // Initialize metrics
    metrics::init_metrics();

    info!("Starting Cloudflare Zero Trust External Authorization Service");

    // Retrieve static keys if provided
    let keys = if let Some(static_keys) = &cli.static_keys {
        Some(
            TeamKeys::from_str(&cli.team_name, static_keys)
                .map_err(|e| anyhow::anyhow!("Error retrieving static keys: {}", e))?,
        )
    } else {
        None
    };

    // Create validator configuration
    #[rustfmt::skip]
    let validator_config = ValidatorConfiguration::Team(
        StaticTeamValidatorConfiguration {
            team_name: cli.team_name.clone(),
            static_keys: keys,
        }
    );

    // Create the bootstrap configuration
    let configuration = Configuration::new(
        &cli.listener,
        validator_config,
        &cli.sync_schedule,
        &cli.nbf_validation,
        &cli.exp_validation,
    );

    run(configuration, cli.audience, cli.observability_port)
        .await
        .map_err(|e| anyhow::anyhow!("Error running server: {}", e))
}

async fn run(
    config: Configuration,
    audiences: Vec<String>,
    observability_port: u16,
) -> AppResult<()> {
    // Initialize health state
    let health_state = Arc::new(HealthState::new());

    // Start health server
    let health_state_clone = Arc::clone(&health_state);
    tokio::spawn(async move {
        if let Err(e) = run_health_server(health_state_clone, observability_port).await {
            error!("Health server error: {}", e);
        }
    });

    // Create validator
    let validator = Arc::new(config.new_validator()?);

    // Create scheduler for key synchronization
    let mut scheduler = JobScheduler::new()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create job scheduler: {}", e))?;

    // Create authorization server
    let server = CloudflareZeroTrustAuthorizationServer::new(
        validator.clone(),
        Arc::new(audiences),
        &config.validator.get_default_team_name(),
        config.nbf_validation,
        config.exp_validation,
    );

    // Run initial sync if needed
    let health_state_clone = Arc::clone(&health_state);
    if config.validator.requires_refresh() {
        info!("Running initial validator synchronization");
        metrics::inc_keys_refresh_total();

        if validator.sync().is_ok() {
            info!("Initial validator synchronization successful");
            health_state_clone.mark_validator_ready();
        } else {
            error!("Initial validator synchronization failed");
            metrics::inc_keys_refresh_errors();
            // Don't mark ready - will retry with scheduler
        }

        info!("Registering validator synchronization job");
        let validator_clone = validator.clone();
        let health_state_job = health_state_clone.clone();

        let sync_job = Job::new_async(config.sync_schedule, move |_uuid, _lock| {
            let validator = validator_clone.clone();
            let health_state = health_state_job.clone();

            Box::pin(async move {
                info!("Triggering validator synchronization");
                metrics::inc_keys_refresh_total();

                match validator.sync() {
                    Ok(_) => {
                        info!("Validator synchronization successful");
                        health_state.mark_validator_ready();
                    }
                    Err(e) => {
                        error!("Validator synchronization failed: {}", e);
                        metrics::inc_keys_refresh_errors();
                        // Don't change ready state on error
                    }
                }
            })
        })
        .map_err(|e| anyhow::anyhow!("Failed to create synchronization job: {}", e))?;

        scheduler
            .add(sync_job)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to add job to scheduler: {}", e))?;
    } else {
        // If no refresh is required, we're immediately ready
        health_state_clone.mark_validator_ready();
    }

    info!("Starting validation synchronization job");
    scheduler
        .start()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start scheduler: {}", e))?;

    info!("Running ExtAuthz server");

    // // Run the server until we receive a termination signal
    // run_until_signal(async { run_server(router, listener).await }).await?;

    info!("Server stopped, shutting down validation synchronization job");
    scheduler
        .shutdown()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to shut down scheduler: {}", e))?;

    Ok(())
}
