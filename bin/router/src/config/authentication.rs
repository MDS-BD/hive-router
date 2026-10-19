use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// AWS Signature Version 4 configuration for signing outgoing subgraph requests.
///
/// ```yaml
/// aws_sig_v4:
///   all:
///     default_chain:
///       region: "us-east-1"
///       service_name: "lambda"
///   subgraphs:
///     products:
///       hardcoded:
///         access_key_id: "AKIA..."
///         secret_access_key: "..."
///         region: "eu-west-1"
///         service_name: "lambda"
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AwsSigV4Config {
    /// Default signing config applied to all subgraphs that lack a per-subgraph override.
    #[serde(default)]
    pub all: AwsSigV4SubgraphConfig,

    /// Per-subgraph overrides.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub subgraphs: HashMap<String, AwsSigV4SubgraphConfig>,
}

impl AwsSigV4Config {
    pub fn is_disabled(&self) -> bool {
        matches!(self.all, AwsSigV4SubgraphConfig::Disabled)
            && (self.subgraphs.is_empty()
                || self
                    .subgraphs
                    .values()
                    .all(|c| matches!(c, AwsSigV4SubgraphConfig::Disabled)))
    }

    pub fn config_for(&self, subgraph_name: &str) -> &AwsSigV4SubgraphConfig {
        self.subgraphs.get(subgraph_name).unwrap_or(&self.all)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum AwsSigV4SubgraphConfig {
    /// Disabled. This is the default for `all` — no signing unless explicitly configured.
    #[default]
    Disabled,
    /// Use the default AWS credential provider chain.
    DefaultChain {
        #[serde(rename = "default_chain")]
        config: DefaultChainConfig,
    },
    /// Use hardcoded credentials.
    Hardcoded {
        #[serde(rename = "hardcoded")]
        config: HardcodedConfig,
    },
}

impl AwsSigV4SubgraphConfig {
    pub fn region(&self) -> Option<&str> {
        match self {
            Self::DefaultChain { config } => Some(&config.region),
            Self::Hardcoded { config } => Some(&config.region),
            Self::Disabled => None,
        }
    }

    pub fn service_name(&self) -> Option<&str> {
        match self {
            Self::DefaultChain { config } => Some(&config.service_name),
            Self::Hardcoded { config } => Some(&config.service_name),
            Self::Disabled => None,
        }
    }

    pub fn assume_role(&self) -> Option<&AssumeRoleConfig> {
        match self {
            Self::DefaultChain { config } => config.assume_role.as_ref(),
            Self::Hardcoded { config } => config.assume_role.as_ref(),
            Self::Disabled => None,
        }
    }

    pub fn payload_signing(&self) -> bool {
        match self {
            Self::DefaultChain { config } => config.payload_signing,
            Self::Hardcoded { config } => config.payload_signing,
            Self::Disabled => true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DefaultChainConfig {
    pub region: String,
    pub service_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assume_role: Option<AssumeRoleConfig>,
    #[serde(default = "default_true")]
    pub payload_signing: bool,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HardcodedConfig {
    pub access_key_id: String,
    #[serde(serialize_with = "redact_secret")]
    pub secret_access_key: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "redact_opt_secret"
    )]
    pub session_token: Option<String>,
    pub region: String,
    pub service_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assume_role: Option<AssumeRoleConfig>,
    #[serde(default = "default_true")]
    pub payload_signing: bool,
}

impl std::fmt::Debug for HardcodedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardcodedConfig")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("region", &self.region)
            .field("service_name", &self.service_name)
            .field("assume_role", &self.assume_role)
            .field("payload_signing", &self.payload_signing)
            .finish()
    }
}

// Manual Clone needed since we removed the derive to hand-write Debug.
impl Clone for HardcodedConfig {
    fn clone(&self) -> Self {
        Self {
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
            region: self.region.clone(),
            service_name: self.service_name.clone(),
            assume_role: self.assume_role.clone(),
            payload_signing: self.payload_signing,
        }
    }
}

fn redact_secret<S: serde::Serializer>(_: &str, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str("[REDACTED]")
}
fn redact_opt_secret<S: serde::Serializer>(_: &Option<String>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_none()
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssumeRoleConfig {
    pub role_arn: String,
    #[serde(default = "default_session_name")]
    pub session_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_session_name() -> String {
    "hive-router".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_by_default() {
        let config: AwsSigV4Config = serde_json::from_str("{}").unwrap();
        assert!(config.is_disabled());
    }

    #[test]
    fn parses_default_chain() {
        let json = r#"{
            "all": {
                "default_chain": {
                    "region": "us-east-1",
                    "service_name": "lambda"
                }
            }
        }"#;
        let config: AwsSigV4Config = serde_json::from_str(json).unwrap();
        match config.config_for("any") {
            AwsSigV4SubgraphConfig::DefaultChain { config: dc } => {
                assert_eq!(dc.region, "us-east-1");
                assert_eq!(dc.service_name, "lambda");
                assert!(dc.payload_signing);
            }
            other => panic!("expected DefaultChain, got {other:?}"),
        }
    }

    #[test]
    fn parses_hardcoded() {
        let json = r#"{
            "all": {
                "hardcoded": {
                    "access_key_id": "AKID",
                    "secret_access_key": "secret",
                    "region": "us-west-2",
                    "service_name": "appsync"
                }
            }
        }"#;
        let config: AwsSigV4Config = serde_json::from_str(json).unwrap();
        match config.config_for("any") {
            AwsSigV4SubgraphConfig::Hardcoded { config: hc } => {
                assert_eq!(hc.access_key_id, "AKID");
                assert_eq!(hc.secret_access_key, "secret");
            }
            other => panic!("expected Hardcoded, got {other:?}"),
        }
    }

    #[test]
    fn parses_per_subgraph_override() {
        let json = r#"{
            "all": { "default_chain": { "region": "us-east-1", "service_name": "lambda" } },
            "subgraphs": {
                "products": { "hardcoded": { "access_key_id": "AKID", "secret_access_key": "s", "region": "eu-west-1", "service_name": "lambda" } }
            }
        }"#;
        let config: AwsSigV4Config = serde_json::from_str(json).unwrap();
        assert!(matches!(
            config.config_for("reviews"),
            AwsSigV4SubgraphConfig::DefaultChain { .. }
        ));
        assert!(matches!(
            config.config_for("products"),
            AwsSigV4SubgraphConfig::Hardcoded { .. }
        ));
    }

    #[test]
    fn parses_with_assume_role_and_unsigned_payload() {
        let json = r#"{
            "all": {
                "default_chain": {
                    "region": "eu-west-1",
                    "service_name": "vpc-lattice-svcs",
                    "payload_signing": false,
                    "assume_role": {
                        "role_arn": "arn:aws:iam::123456789012:role/my-role",
                        "session_name": "hive-router",
                        "external_id": "ext-123"
                    }
                }
            }
        }"#;
        let config: AwsSigV4Config = serde_json::from_str(json).unwrap();
        match config.config_for("any") {
            AwsSigV4SubgraphConfig::DefaultChain { config: dc } => {
                assert!(!dc.payload_signing);
                let ar = dc.assume_role.as_ref().unwrap();
                assert_eq!(ar.role_arn, "arn:aws:iam::123456789012:role/my-role");
                assert_eq!(ar.external_id.as_deref(), Some("ext-123"));
            }
            other => panic!("expected DefaultChain, got {other:?}"),
        }
    }
}
