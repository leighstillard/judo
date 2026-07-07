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
        // ponytail: env-config is the skeleton's stand-in for a real config section.
        let rp_id = std::env::var("JUDO_RP_ID").unwrap_or_else(|_| "judo.dev".to_string());
        let rp_origin = std::env::var("JUDO_RP_ORIGIN")
            .unwrap_or_else(|_| "https://approve.judo.dev".to_string());
        let enroll_origin =
            std::env::var("JUDO_ENROLL_ORIGIN").unwrap_or_else(|_| format!("https://{rp_id}"));

        let approve = Url::parse(&rp_origin)?;
        let enroll = Url::parse(&enroll_origin)?;
        let inner = WebauthnBuilder::new(&rp_id, &approve)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use serde_json::Value;

    #[test]
    fn new_reads_rp_id_from_env() {
        let _guard = test_support::env_lock().lock().expect("env lock poisoned");
        std::env::set_var("JUDO_RP_ID", "judo.stillard.com");
        std::env::set_var("JUDO_RP_ORIGIN", "https://judo.stillard.com");
        std::env::remove_var("JUDO_ENROLL_ORIGIN");

        let verifier = WebauthnVerifier::new().expect("build verifier");
        let (options_json, _) = verifier
            .start_registration("alice")
            .expect("start registration");
        let options: Value = serde_json::from_str(&options_json).expect("registration JSON");

        assert_eq!(options["publicKey"]["rp"]["id"], "judo.stillard.com");

        std::env::remove_var("JUDO_RP_ID");
        std::env::remove_var("JUDO_RP_ORIGIN");
        std::env::remove_var("JUDO_ENROLL_ORIGIN");
    }
}
