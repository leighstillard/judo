use crate::config::{self, Identity, StoredPasskey};
use anyhow::{anyhow, Context, Result};
use std::net::IpAddr;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Uuid, Webauthn as InnerWebauthn, WebauthnBuilder,
};

#[derive(Clone)]
pub struct WebauthnVerifier {
    inner: Option<InnerWebauthn>,
    config_error: Option<String>,
}

impl WebauthnVerifier {
    pub fn new(relay_url: &str) -> Result<Self> {
        let (rp_id, rp_origin) = config::rp_from_relay(relay_url)?;
        let enroll_origin = std::env::var("JUDO_ENROLL_ORIGIN").unwrap_or(rp_origin.clone());

        let approve = Url::parse(&rp_origin)?;
        let enroll = Url::parse(&enroll_origin)?;
        let inner = WebauthnBuilder::new(&rp_id, &approve)
            .context("invalid WebAuthn RP configuration")
            .and_then(|builder| {
                builder
                    .rp_name("judo")
                    .allow_subdomains(true)
                    .append_allowed_origin(&enroll)
                    .build()
                    .context("failed to build WebAuthn verifier")
            });
        match inner {
            Ok(inner) => Ok(Self {
                inner: Some(inner),
                config_error: None,
            }),
            Err(error) if is_headless_dev_rp(&rp_id, &rp_origin) => Ok(Self {
                inner: None,
                config_error: Some(format!("{error:#}")),
            }),
            Err(error) => Err(error),
        }
    }

    pub fn start_registration(&self, user_name: &str) -> Result<(String, PasskeyRegistration)> {
        let (options, state) = self
            .inner()?
            .start_passkey_registration(Uuid::new_v4(), user_name, user_name, None)
            .context("failed to start passkey registration")?;
        Ok((serde_json::to_string(&options)?, state))
    }

    pub fn finish_registration(
        &self,
        response_json: &str,
        state: &PasskeyRegistration,
        label: &str,
    ) -> Result<StoredPasskey> {
        let response: RegisterPublicKeyCredential = serde_json::from_str(response_json)
            .context("registration response is not valid WebAuthn JSON")?;
        let passkey = self
            .inner()?
            .finish_passkey_registration(&response, state)
            .context("passkey registration failed")?;
        Ok(StoredPasskey {
            label: label.to_string(),
            passkey_json: serde_json::to_string(&passkey)?,
        })
    }

    pub fn start_authentication(
        &self,
        identity: &Identity,
    ) -> Result<(String, PasskeyAuthentication)> {
        let passkeys = load_passkeys(identity)?;
        let (options, state) = self
            .inner()?
            .start_passkey_authentication(&passkeys)
            .context("failed to start passkey authentication")?;
        Ok((serde_json::to_string(&options)?, state))
    }

    pub fn finish_authentication(
        &self,
        response_json: &str,
        state: &PasskeyAuthentication,
    ) -> Result<()> {
        let response: PublicKeyCredential = serde_json::from_str(response_json)
            .context("assertion response is not valid WebAuthn JSON")?;
        self.inner()?
            .finish_passkey_authentication(&response, state)
            .context("passkey authentication failed")?;
        Ok(())
    }

    fn inner(&self) -> Result<&InnerWebauthn> {
        self.inner.as_ref().ok_or_else(|| {
            anyhow!(
                "WebAuthn ceremonies are unavailable: {}",
                self.config_error
                    .as_deref()
                    .unwrap_or("verifier was not configured")
            )
        })
    }
}

fn is_headless_dev_rp(rp_id: &str, origin: &str) -> bool {
    origin.starts_with("http://") && (rp_id == "localhost" || rp_id.parse::<IpAddr>().is_ok())
}

fn load_passkeys(identity: &Identity) -> Result<Vec<Passkey>> {
    identity
        .passkeys
        .iter()
        .map(|p| serde_json::from_str(&p.passkey_json).context("stored passkey JSON is invalid"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn new_derives_rp_id_from_relay_url() {
        let verifier =
            WebauthnVerifier::new("wss://judo.stillard.com/daemon").expect("build verifier");
        let (options_json, _) = verifier
            .start_registration("alice")
            .expect("start registration");
        let options: Value = serde_json::from_str(&options_json).expect("registration JSON");

        assert_eq!(options["publicKey"]["rp"]["id"], "judo.stillard.com");
    }

    #[test]
    fn new_accepts_ws_ip_relay_for_headless_dev() {
        WebauthnVerifier::new("ws://127.0.0.1:8787/daemon").expect("build verifier");
    }
}
