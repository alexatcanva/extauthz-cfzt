use prometheus::{
    register_counter_vec, register_histogram, register_int_counter, register_int_gauge,
    CounterVec, Histogram, IntCounter, IntGauge,
};
use std::sync::Once;

// Ensure metrics are only registered once
static METRICS_INIT: Once = Once::new();

// Metrics
static mut REQUESTS_TOTAL: Option<IntCounter> = None;
static mut REQUESTS_DURATION: Option<Histogram> = None;
static mut VALIDATION_RESULTS: Option<CounterVec> = None;
static mut KEYS_REFRESH_TOTAL: Option<IntCounter> = None;
static mut KEYS_REFRESH_ERRORS: Option<IntCounter> = None;
static mut VALIDATOR_READY: Option<IntGauge> = None;

/// Initialize metrics
pub fn init_metrics() {
    METRICS_INIT.call_once(|| {
        unsafe {
            REQUESTS_TOTAL = Some(
                register_int_counter!(
                    "extauthz_cfzt_requests_total",
                    "Total number of authorization requests"
                )
                .unwrap(),
            );

            REQUESTS_DURATION = Some(
                register_histogram!(
                    "extauthz_cfzt_request_duration_seconds",
                    "Request duration in seconds",
                    vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
                )
                .unwrap(),
            );

            VALIDATION_RESULTS = Some(
                register_counter_vec!(
                    "extauthz_cfzt_validation_results",
                    "Validation results",
                    &["result"]
                )
                .unwrap(),
            );

            KEYS_REFRESH_TOTAL = Some(
                register_int_counter!(
                    "extauthz_cfzt_keys_refresh_total",
                    "Total number of key refresh operations"
                )
                .unwrap(),
            );

            KEYS_REFRESH_ERRORS = Some(
                register_int_counter!(
                    "extauthz_cfzt_keys_refresh_errors",
                    "Number of key refresh errors"
                )
                .unwrap(),
            );

            VALIDATOR_READY = Some(
                register_int_gauge!(
                    "extauthz_cfzt_validator_ready",
                    "Whether the validator is ready"
                )
                .unwrap(),
            );
        }
    });
}

/// Increment the total number of requests
pub fn inc_requests_total() {
    unsafe {
        if let Some(counter) = &REQUESTS_TOTAL {
            counter.inc();
        }
    }
}

/// Record the duration of a request
pub fn observe_request_duration(duration: f64) {
    unsafe {
        if let Some(histogram) = &REQUESTS_DURATION {
            histogram.observe(duration);
        }
    }
}

/// Increment the validation results counter
pub fn inc_validation_result(result: &str) {
    unsafe {
        if let Some(counter) = &VALIDATION_RESULTS {
            counter.with_label_values(&[result]).inc();
        }
    }
}

/// Increment the total number of key refresh operations
pub fn inc_keys_refresh_total() {
    unsafe {
        if let Some(counter) = &KEYS_REFRESH_TOTAL {
            counter.inc();
        }
    }
}

/// Increment the number of key refresh errors
pub fn inc_keys_refresh_errors() {
    unsafe {
        if let Some(counter) = &KEYS_REFRESH_ERRORS {
            counter.inc();
        }
    }
}

/// Set the validator ready state
pub fn set_validator_ready(ready: bool) {
    unsafe {
        if let Some(gauge) = &VALIDATOR_READY {
            if ready {
                gauge.set(1);
            } else {
                gauge.set(0);
            }
        }
    }
}

/// Gather metrics as a string
pub fn gather_metrics() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let mut buffer = Vec::new();
    
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        return format!("Error encoding metrics: {}", e);
    }
    
    String::from_utf8(buffer).unwrap_or_else(|_| "Error converting metrics to string".to_string())
}