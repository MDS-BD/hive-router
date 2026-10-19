use std::{collections::HashMap, collections::HashSet, sync::Arc};

use reqsign_aws_v4::{
    AssumeRoleCredentialProvider, DefaultCredentialProvider, RequestSigner,
    StaticCredentialProvider,
};
use reqsign_core::{Context, OsEnv, ProvideCredentialChain, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

use crate::config::authentication::{
    AssumeRoleConfig, AwsSigV4Config, AwsSigV4SubgraphConfig, DefaultChainConfig,
};

#[derive(Clone)]
pub struct AwsSigner {
    signer: Signer<reqsign_aws_v4::Credential>,
    pub payload_signing: bool,
}

impl AwsSigner {
    pub async fn sign(
        &self,
        parts: &mut http::request::Parts,
        body: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.payload_signing {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(body);
            parts.headers.insert(
                http::header::HeaderName::from_static("x-amz-content-sha256"),
                http::HeaderValue::from_str(&hex::encode(hasher.finalize()))?,
            );
        }
        self.signer.sign(parts, None).await?;
        Ok(())
    }

    /// Sign with an unsigned payload (x-amz-content-sha256: UNSIGNED-PAYLOAD).
    pub async fn sign_unsigned(
        &self,
        parts: &mut http::request::Parts,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        parts.headers.insert(
            http::header::HeaderName::from_static("x-amz-content-sha256"),
            http::HeaderValue::from_static("UNSIGNED-PAYLOAD"),
        );
        self.signer.sign(parts, None).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SubgraphAuthRuntime {
    signers: Arc<HashMap<String, Arc<AwsSigner>>>,
    /// Subgraphs explicitly disabled — must NOT fall back to default_signer.
    disabled: Arc<HashSet<String>>,
    default_signer: Option<Arc<AwsSigner>>,
}

impl SubgraphAuthRuntime {
    pub async fn from_config(
        config: &AwsSigV4Config,
    ) -> Result<Option<Self>, Box<dyn std::error::Error + Send + Sync>> {
        if config.is_disabled() {
            return Ok(None);
        }

        let ctx = Context::new()
            .with_file_read(TokioFileRead::default())
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);

        let default_signer = match &config.all {
            AwsSigV4SubgraphConfig::Disabled => None,
            other => Some(Arc::new(build_signer(&ctx, other)?)),
        };

        let mut signers = HashMap::new();
        let mut disabled = HashSet::new();
        for (name, cfg) in &config.subgraphs {
            match cfg {
                AwsSigV4SubgraphConfig::Disabled => {
                    disabled.insert(name.clone());
                }
                other => {
                    signers.insert(name.clone(), Arc::new(build_signer(&ctx, other)?));
                }
            }
        }

        Ok(Some(Self {
            signers: Arc::new(signers),
            disabled: Arc::new(disabled),
            default_signer,
        }))
    }

    pub fn get(&self, subgraph_name: &str) -> Option<&Arc<AwsSigner>> {
        self.signers.get(subgraph_name).or_else(|| {
            // Only fall back to default if not explicitly disabled
            if self.disabled.contains(subgraph_name) {
                None
            } else {
                self.default_signer.as_ref()
            }
        })
    }
}

fn build_signer(
    ctx: &Context,
    config: &AwsSigV4SubgraphConfig,
) -> Result<AwsSigner, Box<dyn std::error::Error + Send + Sync>> {
    let (service_name, region) = match config {
        AwsSigV4SubgraphConfig::DefaultChain { config: dc } => {
            (dc.service_name.clone(), dc.region.clone())
        }
        AwsSigV4SubgraphConfig::Hardcoded { config: hc } => {
            (hc.service_name.clone(), hc.region.clone())
        }
        AwsSigV4SubgraphConfig::Disabled => unreachable!(),
    };

    let loader = match config {
        AwsSigV4SubgraphConfig::DefaultChain { config: dc } => {
            let base = build_default_chain(dc);
            match &dc.assume_role {
                Some(ar) => build_assume_role_chain(ctx, ar, &region, base)?,
                None => ProvideCredentialChain::new().push(base),
            }
        }
        AwsSigV4SubgraphConfig::Hardcoded { config: hc } => {
            let mut provider =
                StaticCredentialProvider::new(&hc.access_key_id, &hc.secret_access_key);
            if let Some(tok) = &hc.session_token {
                provider = provider.with_session_token(tok);
            }
            match &hc.assume_role {
                Some(ar) => ProvideCredentialChain::new()
                    .push(build_assume_role_loader(ctx, ar, &region, provider)?),
                None => ProvideCredentialChain::new().push(provider),
            }
        }
        AwsSigV4SubgraphConfig::Disabled => unreachable!(),
    };

    let signer = Signer::new(
        ctx.clone(),
        loader,
        RequestSigner::new(&service_name, &region),
    );

    Ok(AwsSigner {
        signer,
        payload_signing: config.payload_signing(),
    })
}

fn build_default_chain(dc: &DefaultChainConfig) -> DefaultCredentialProvider {
    let mut builder = DefaultCredentialProvider::builder();
    if let Some(profile) = &dc.profile_name {
        builder = builder.configure_profile(|p| p.with_profile(profile));
    }
    builder.build()
}

fn build_assume_role_chain(
    ctx: &Context,
    ar: &AssumeRoleConfig,
    region: &str,
    base: DefaultCredentialProvider,
) -> Result<
    ProvideCredentialChain<reqsign_aws_v4::Credential>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let sts_signer = Signer::new(ctx.clone(), base, RequestSigner::new("sts", region));
    let assume_role = build_assume_role(ar, sts_signer, region);
    Ok(ProvideCredentialChain::new().push(assume_role))
}

fn build_assume_role_loader(
    ctx: &Context,
    ar: &AssumeRoleConfig,
    region: &str,
    base: impl reqsign_core::ProvideCredential<Credential = reqsign_aws_v4::Credential> + 'static,
) -> Result<AssumeRoleCredentialProvider, Box<dyn std::error::Error + Send + Sync>> {
    let sts_signer = Signer::new(ctx.clone(), base, RequestSigner::new("sts", region));
    Ok(build_assume_role(ar, sts_signer, region))
}

fn build_assume_role(
    ar: &AssumeRoleConfig,
    sts_signer: Signer<reqsign_aws_v4::Credential>,
    region: &str,
) -> AssumeRoleCredentialProvider {
    let mut provider = AssumeRoleCredentialProvider::new(ar.role_arn.clone(), sts_signer)
        .with_role_session_name(ar.session_name.clone())
        .with_region(region.to_string());
    if let Some(eid) = &ar.external_id {
        provider = provider.with_external_id(eid.clone());
    }
    provider
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::authentication::{AwsSigV4Config, HardcodedConfig};

    fn hardcoded_config(key: &str, secret: &str) -> AwsSigV4Config {
        let json = format!(
            r#"{{
            "all": {{ "hardcoded": {{ "access_key_id": "{key}", "secret_access_key": "{secret}", "region": "us-east-1", "service_name": "s3" }} }}
        }}"#
        );
        serde_json::from_str(&json).unwrap()
    }

    #[tokio::test]
    async fn builds_and_signs() {
        let config = hardcoded_config(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        );
        let svc = SubgraphAuthRuntime::from_config(&config)
            .await
            .unwrap()
            .unwrap();
        let signer = svc.get("any").unwrap();

        let req = http::Request::post("https://s3.us-east-1.amazonaws.com/bucket/key")
            .header("Content-Type", "application/json")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        signer.sign(&mut parts, b"hello").await.unwrap();

        let auth = parts
            .headers
            .get("Authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256"));
        assert!(auth.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(auth.contains("us-east-1/s3"));
        assert!(auth.contains("Signature="));
    }

    #[tokio::test]
    async fn unsigned_payload_for_lattice() {
        let json = r#"{
            "all": { "hardcoded": { "access_key_id": "A", "secret_access_key": "B", "region": "us-east-1", "service_name": "vpc-lattice-svcs", "payload_signing": false } }
        }"#;
        let config: AwsSigV4Config = serde_json::from_str(json).unwrap();
        let svc = SubgraphAuthRuntime::from_config(&config)
            .await
            .unwrap()
            .unwrap();
        let signer = svc.get("any").unwrap();

        let (mut parts, _) = http::Request::post("https://example.com/")
            .body(())
            .unwrap()
            .into_parts();
        signer.sign(&mut parts, b"body").await.unwrap();

        assert_eq!(
            parts
                .headers
                .get("x-amz-content-sha256")
                .unwrap()
                .to_str()
                .unwrap(),
            "UNSIGNED-PAYLOAD"
        );
    }

    #[tokio::test]
    async fn disabled_config_returns_none() {
        let config = AwsSigV4Config::default();
        assert!(SubgraphAuthRuntime::from_config(&config)
            .await
            .unwrap()
            .is_none());
    }
}
