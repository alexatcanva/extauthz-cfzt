// Replace jnt::sockets::Listener with our custom implementation
use crate::sockets::Listener;

use anyhow::{anyhow, Result};
use clap::ValueEnum;
use rust_cfzt_validator::api::TeamKeys;
use rust_cfzt_validator::Validator;

#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum TimeConstraintMode {
    Strict,
    Lax,
}

pub struct StaticTeamValidatorConfiguration {
    pub team_name: String,
    pub static_keys: Option<TeamKeys>,
}

impl StaticTeamValidatorConfiguration {
    pub fn is_static_keys(&self) -> bool {
        self.static_keys.is_some()
    }
}

pub enum ValidatorConfiguration {
    Team(StaticTeamValidatorConfiguration),
}

impl ValidatorConfiguration {
    pub fn get_default_team_name(&self) -> String {
        match self {
            Self::Team(config) => config.team_name.to_string(),
        }
    }

    pub fn requires_refresh(&self) -> bool {
        match self {
            Self::Team(config) => !config.is_static_keys(),
        }
    }
}

pub struct Configuration {
    pub listener: String,
    pub validator: ValidatorConfiguration,
    pub sync_schedule: String,
    pub nbf_validation: TimeConstraintMode,
    pub exp_validation: TimeConstraintMode,
}

impl Configuration {
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

    // Use our custom Listener implementation
    pub fn open_listener(&self) -> Result<Listener> {
        let url = url::Url::parse(&self.listener)?;
        Listener::from_url(url).map_err(|err| anyhow!("Failed to open listener: {:?}", err))
    }

    pub fn new_validator(&self) -> Result<Box<dyn Validator>> {
        crate::server::validator::new_validator(&self.validator)
    }
}
