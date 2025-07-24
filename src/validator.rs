use crate::error::{AppError, AppResult};
use crate::schema::ValidatorConfiguration;
use rust_cfzt_validator::{TeamValidator, Validator};

/// Create a new team validator
fn new_single_team_configuration(team_name: &str) -> AppResult<TeamValidator> {
    TeamValidator::from_team_name(team_name)
        .map_err(|e| AppError::ValidationError(format!("Failed to create team validator: {}", e)))
}

/// Create a new validator based on the configuration
pub fn new_validator(configuration: &ValidatorConfiguration) -> AppResult<Box<dyn Validator>> {
    match configuration {
        ValidatorConfiguration::Team(config) => {
            Ok(Box::new(new_single_team_configuration(&config.team_name)?))
        }
    }
}
