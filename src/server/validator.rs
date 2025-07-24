use crate::config::bootstrap::schema::ValidatorConfiguration;
use anyhow::{Result, anyhow};
use rust_cfzt_validator::{TeamValidator, Validator};

fn new_single_team_configuration(team_name: &str) -> Result<TeamValidator> {
    TeamValidator::from_team_name(team_name).map_err(|e| anyhow!("Failed to create team validator: {}", e))
}

pub fn new_validator(configuration: &ValidatorConfiguration) -> Result<Box<dyn Validator>> {
    match configuration {
        ValidatorConfiguration::Team(config) => {
            Ok(Box::new(new_single_team_configuration(&config.team_name)?))
        }
    }
}
