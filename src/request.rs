use anyhow::{anyhow, Result};
use envoy_types::ext_authz::v3::{pb::CheckRequest, CheckRequestExt};
use serde_json::Value;
use std::collections::HashMap;
use tonic::Status;

/// Get headers from a check request
pub fn get_headers(req: &CheckRequest) -> Result<&HashMap<String, String>, Status> {
    req.get_client_headers()
        .ok_or_else(|| Status::invalid_argument("headers not provided by envoy"))
}

/// Integer type for JWT claims
type ClaimInteger = u64;

/// User assertion from a JWT
pub struct UserAssertion {
    pub aud: Vec<String>,
    pub email: String,
    pub exp: ClaimInteger,
    pub iat: ClaimInteger,
    pub nbf: ClaimInteger,
    pub iss: String,
    pub typ: String,
    pub nonce: String,
    pub sub: String,
    pub country: String,
    pub custom: HashMap<String, String>,
}

/// Get a required claim from a JSON object
fn get_required_claim<'a>(
    object: &'a serde_json::map::Map<String, Value>,
    claim: &str,
) -> Result<&'a Value> {
    object.get(claim).ok_or_else(|| anyhow!("{} claim missing", claim))
}

/// Get a required string claim from a JSON object
fn get_required_str_claim(
    object: &serde_json::map::Map<String, Value>,
    claim: &str,
) -> Result<String> {
    get_required_claim(object, claim)?
        .as_str()
        .ok_or_else(|| anyhow!("{} claim should be str", claim))
        .map(|s| s.to_string())
}

/// Get a required integer claim from a JSON object
fn get_required_int_claim(
    object: &serde_json::map::Map<String, Value>,
    claim: &str,
) -> Result<ClaimInteger> {
    get_required_claim(object, claim)?
        .as_u64()
        .ok_or_else(|| anyhow!("{} claim should be int", claim))
}

/// Collect audiences from a JSON object
fn collect_audiences(object: &serde_json::map::Map<String, Value>) -> Result<Vec<String>> {
    let mut audiences: Vec<String> = vec![];

    for audience in get_required_claim(object, "aud")?
        .as_array()
        .ok_or_else(|| anyhow!("aud must be array"))?
    {
        audiences.push(
            audience
                .as_str()
                .ok_or_else(|| anyhow!("audience values must be str"))?
                .to_string(),
        );
    }

    Ok(audiences)
}

/// Force a JSON value to a string
fn force_as_string(value: &Value) -> String {
    match value.as_str() {
        Some(strval) => strval.to_string(),
        None => value.to_string(),
    }
}

/// Get custom claims from a JSON object
fn get_custom_claims(
    object: &serde_json::map::Map<String, Value>,
) -> Result<HashMap<String, String>> {
    match object.get("custom") {
        Some(value) => {
            let mut claims: HashMap<String, String> = HashMap::new();
            let custom_obj = value.as_object().ok_or_else(|| anyhow!("custom claim must be obj"))?;

            for (custom_claim, custom_val) in custom_obj.into_iter() {
                claims.insert(custom_claim.to_string(), force_as_string(custom_val));
            }

            Ok(claims)
        }
        None => Ok(HashMap::new()),
    }
}

impl UserAssertion {
    /// Create a user assertion from a claims object
    fn from_claims_object(object: &serde_json::map::Map<String, Value>) -> Result<Self> {
        Ok(UserAssertion {
            aud: collect_audiences(object)?,
            email: get_required_str_claim(object, "email")?,
            exp: get_required_int_claim(object, "exp")?,
            iat: get_required_int_claim(object, "iat")?,
            nbf: get_required_int_claim(object, "nbf")?,
            iss: get_required_str_claim(object, "iss")?,
            typ: get_required_str_claim(object, "type")?,
            nonce: get_required_str_claim(object, "identity_nonce")?,
            sub: get_required_str_claim(object, "sub")?,
            country: get_required_str_claim(object, "country")?,
            custom: get_custom_claims(object)?,
        })
    }
}

/// Service assertion from a JWT
pub struct ServiceAssertion {
    pub aud: Vec<String>,
    pub exp: ClaimInteger,
    pub iat: ClaimInteger,
    pub iss: String,
    pub typ: String,
    pub common_name: String,
}

impl ServiceAssertion {
    /// Create a service assertion from a claims object
    fn from_claims_object(object: &serde_json::map::Map<String, Value>) -> Result<Self> {
        Ok(ServiceAssertion {
            aud: collect_audiences(object)?,
            exp: get_required_int_claim(object, "exp")?,
            iat: get_required_int_claim(object, "iat")?,
            iss: get_required_str_claim(object, "iss")?,
            typ: get_required_str_claim(object, "type")?,
            common_name: get_required_str_claim(object, "common_name")?,
        })
    }
}

/// Principal assertion from a JWT (either user or service)
pub enum PrincipalAssertion {
    User(UserAssertion),
    Service(ServiceAssertion),
}

impl PrincipalAssertion {
    /// Create a principal assertion from a claims value
    pub fn from_claims_value(val: &serde_json::Value) -> Result<Self> {
        let object = val.as_object().ok_or_else(|| anyhow!("invalid claims value"))?;
        let subject = object
            .get("sub")
            .ok_or_else(|| anyhow!("sub claim missing"))?
            .as_str()
            .ok_or_else(|| anyhow!("sub claim must be str"))?;

        if subject.is_empty() {
            return Ok(Self::Service(ServiceAssertion::from_claims_object(object)?));
        }

        Ok(Self::User(UserAssertion::from_claims_object(object)?))
    }
}