use thiserror::Error;

/// Application-wide error types
#[derive(Error, Debug)]
pub enum AppError {
    /// Validation error
    #[error("validation error: {0}")]
    ValidationError(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// IO error
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    /// JWT error
    #[error("jwt error: {0}")]
    JwtError(String),

    /// Server error
    #[error("server error: {0}")]
    ServerError(String),

    /// Tonic transport error
    #[error("transport error: {0}")]
    TonicError(#[from] tonic::transport::Error),

    /// Scheduler error
    #[error("scheduler error: {0}")]
    SchedulerError(String),

    /// General error
    #[error("{0}")]
    General(#[from] anyhow::Error),
}

/// Result type with AppError as the error type
pub type AppResult<T> = Result<T, AppError>;
