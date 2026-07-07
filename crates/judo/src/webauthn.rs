use crate::config::{Identity, StoredPasskey};
use anyhow::{Context, Result};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Uuid, Webauthn as InnerWebauthn, WebauthnBuilder,
};

#[derive(Clone)]
pub struct WebauthnVerifier {
    inner: InnerWebauthn,
}

impl WebauthnVerifier {
    pub fn new() -> Result<Self> {
        let approve = Url::parse("https://approve.judo.dev")?;
        let enroll = Url::parse("https://judo.dev")?;
        let inner = WebauthnBuilder::new("judo.dev", &approve)
            .context("invalid WebAuthn RP configuration")?
            .rp_name("judo")
            .allow_subdomains(true)
            .append_allowed_origin(&enroll)
            .build()
            .context("failed to build WebAuthn verifier")?;
        Ok(Self { inner })
    }

    pub fn start_registration(&self, user_name: &str) -> Result<(String, PasskeyRegistration)> {
        let (options, state) = self
            .inner
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
            .inner
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
            .inner
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
        self.inner
            .finish_passkey_authentication(&response, state)
            .context("passkey authentication failed")?;
        Ok(())
    }
}

fn load_passkeys(identity: &Identity) -> Result<Vec<Passkey>> {
    identity
        .passkeys
        .iter()
        .map(|p| serde_json::from_str(&p.passkey_json).context("stored passkey JSON is invalid"))
        .collect()
}
