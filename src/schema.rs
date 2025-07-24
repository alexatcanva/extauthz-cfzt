use crate::error::AppResult;
use clap::ValueEnum;
use rust_cfzt_validator::api::TeamKeys;
use rust_cfzt_validator::Validator;

/// The time constraint validation mode
#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum TimeConstraintMode {
    /// Strict validation
    Strict,
    /// Lax validation (ignores time constraints)
    Lax,
}

/// Configuration for a static team validator
pub struct StaticTeamValidatorConfiguration {
    pub team_name: String,
    pub static_keys: Option<TeamKeys>,
}

impl StaticTeamValidatorConfiguration {
    /// Check if this configuration uses static keys
    pub fn is_static_keys(&self) -> bool {
        self.static_keys.is_some()
    }
}

/// Validator configuration
pub enum ValidatorConfiguration {
    /// Team validator configuration
    Team(StaticTeamValidatorConfiguration),
}

impl ValidatorConfiguration {
    /// Get the default team name from the configuration
    pub fn get_default_team_name(&self) -> String {
        match self {
            Self::Team(config) => config.team_name.to_string(),
        }
    }

    /// Check if this configuration requires key refresh
    pub fn requires_refresh(&self) -> bool {
        match self {
            Self::Team(config) => !config.is_static_keys(),
        }
    }
}

/// Application configuration
pub struct Configuration {
    /// Socket URL string (tcp://host:port or unix:///path/to/socket)
    pub listener: String,
    /// Validator configuration
    pub validator: ValidatorConfiguration,
    /// Cron schedule for key synchronization
    pub sync_schedule: String,
    /// Not before (NBF) validation mode
    pub nbf_validation: TimeConstraintMode,
    /// Expiry validation mode
    pub exp_validation: TimeConstraintMode,
}

impl Configuration {
    /// Create a new configuration
    pub fn new(
        listener: &str,
        validator_config: ValidatorConfiguration,
        sync_schedule: &str,
        nbf_validation: &TimeConstraintMode,
        exp_validation: &TimeConstraintMode,
    ) -> Self {
        Configuration {
            listener: listener.to_string(),
            validator: validator_config,
            sync_schedule: sync_schedule.to_string(),
            nbf_validation: nbf_validation.clone(),
            exp_validation: exp_validation.clone(),
        }
    }

    /// Create a new configuration for a single team
    pub fn new_single_team_configuration(
        listener: &str,
        team_name: &str,
        static_keys: Option<TeamKeys>,
        sync_schedule: &str,
        nbf_validation: &TimeConstraintMode,
        exp_validation: &TimeConstraintMode,
    ) -> Self {
        Configuration::new(
            listener,
            ValidatorConfiguration::Team(StaticTeamValidatorConfiguration {
                team_name: team_name.to_string(),
                static_keys,
            }),
            sync_schedule,
            nbf_validation,
            exp_validation,
        )
    }

    /// Create a new validator based on the configuration
    pub fn new_validator(&self) -> AppResult<Box<dyn Validator>> {
        crate::validator::new_validator(&self.validator)
    }
}
