# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `extauthz-cfzt`, a Rust-based external authorization service designed to work with Envoy proxy for validating Cloudflare Zero Trust JWT tokens. It implements the Envoy External Authorization (ExtAuthz) API to provide a validation service for JWTs issued by Cloudflare Zero Trust.

## Building and Running

### Building the Project

```bash
# Build in debug mode
cargo build

# Build in release mode
cargo build --release

# Build for production with musl (static linking)
cargo build --release --target=$(arch)-unknown-linux-musl
```

### Running Tests

```bash
# Run tests
cargo test
```

### Building Docker Image

```bash
# Build the Docker image
docker build -t extauthz-cfzt .
```

## Configuration

The service is configured through environment variables:

- `LISTENER` - Socket to listen on (default: "tcp://[::1]:10000")
- `TEAM_NAME` - Cloudflare team name (required)
- `STATIC_KEYS` - Static JWT verification keys (optional)
- `NBF_VALIDATION` - "strict" or "lax" for Not Before validation (default: "strict")
- `EXP_VALIDATION` - "strict" or "lax" for Expiration validation (default: "strict")
- `SYNC_SCHEDULE` - Cron schedule for key synchronization (default: "0 0 0 * * *")
- `AUDIENCE_PROVIDER` - Provider type for audience validation (default: "static")
- `AUDIENCE` - Single audience value for validation
- `AUDIENCES` - Comma-separated list of audiences for validation

## Architecture

### Core Components

1. **ExtAuthz Server** - Implements the Envoy External Authorization API to validate JWTs
   - Main implementation in `src/server/extauthz.rs`

2. **Validator** - Validates Cloudflare Zero Trust JWT tokens
   - Uses the `rust-cfzt-validator` crate
   - Supports static keys or fetching keys from Cloudflare

3. **Audience Provider** - Provides audience values for JWT validation
   - Currently only supports static audiences

4. **Configuration** - Environment-based configuration system
   - Bootstrap configuration: `src/config/bootstrap/discovery.rs`
   - Audience configuration: `src/config/audience/discovery.rs`

5. **Server Runtime** - Tokio-based async runtime with multi-threading support
   - Uses cron scheduling for key synchronization

### Request Flow

1. Envoy sends authorization requests to the service
2. Service extracts JWT from the "cf-access-jwt-assertion" header
3. JWT is validated against Cloudflare keys
4. If valid, a successful response is returned with principal information
5. If invalid, an error response is returned

## Common Development Tasks

### Adding a New Audience Provider

1. Define a new struct in `src/config/audience/schema.rs` implementing the `AudienceProvider` trait
2. Add discovery logic in `src/config/audience/discovery.rs`
3. Update the `discover_audience_provider` function to handle the new provider type

### Modifying Validation Logic

The JWT validation logic is in `src/server/extauthz.rs` in the `validate` method of the `CloudflareZeroTrustAuthorizationServer` struct.