use crate::config::audience::schema::{AudienceProvider, StaticAudienceProvider};
use anyhow::{Result, anyhow};
use std::env;

// Helper function to get environment variables with defaults
fn get_env_with_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

// Environment variable accessors
fn discover_audience_provider_str() -> String {
    get_env_with_default("AUDIENCE_PROVIDER", "static")
}

fn discover_audience_str() -> String {
    get_env_with_default("AUDIENCE", "")
}

fn discover_audiences_str() -> String {
    get_env_with_default("AUDIENCES", "")
}

type AudProviderResult = Result<Box<dyn AudienceProvider>>;

fn discover_audience() -> Option<StaticAudienceProvider> {
    let audience_str = discover_audience_str();

    if audience_str.is_empty() {
        return None;
    }

    Some(StaticAudienceProvider::new_single_aud(&audience_str))
}

fn discover_audiences() -> Option<StaticAudienceProvider> {
    let audiences_str = discover_audiences_str();

    if audiences_str.is_empty() {
        return None;
    }

    let audiences: Vec<String> = audiences_str.split(",").map(|s| s.to_string()).collect();
    Some(StaticAudienceProvider::new(audiences))
}

fn discover_static_provider() -> AudProviderResult {
    match discover_audience().or(discover_audiences()) {
        Some(provider) => Ok(Box::new(provider)),
        None => Err(anyhow!("No audience configured for static provider")),
    }
}

pub fn discover_audience_provider() -> AudProviderResult {
    match discover_audience_provider_str().to_lowercase().as_str() {
        "static" => discover_static_provider(),
        _ => Err(anyhow!("Invalid audience provider")),
    }
}
