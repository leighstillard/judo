use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use judo_proto::EnvelopeBody;
use rand::{rngs::OsRng, RngCore};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

pub fn seal(body: &EnvelopeBody) -> Result<(String, String)> {
    let plaintext = serde_json::to_vec(body)?;
    let mut key = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("invalid XChaCha20-Poly1305 key length"))?;
    let mut sealed = Vec::with_capacity(NONCE_LEN + plaintext.len() + 16);
    sealed.extend_from_slice(&nonce);
    sealed.extend(
        cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext.as_slice())
            .map_err(|_| anyhow!("envelope encryption failed"))?,
    );

    Ok((STANDARD.encode(sealed), STANDARD.encode(key)))
}

pub fn open(ciphertext_b64: &str, key_b64: &str) -> Result<EnvelopeBody> {
    let sealed = STANDARD
        .decode(ciphertext_b64)
        .context("ciphertext is not valid base64")?;
    if sealed.len() <= NONCE_LEN {
        bail!("ciphertext is too short");
    }
    let key = STANDARD
        .decode(key_b64)
        .context("key is not valid base64")?;
    if key.len() != KEY_LEN {
        bail!("key must be 32 bytes");
    }

    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("invalid XChaCha20-Poly1305 key length"))?;
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("envelope decryption failed"))?;
    Ok(serde_json::from_slice(&plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> EnvelopeBody {
        EnvelopeBody {
            argv: vec!["sudo".to_string(), "whoami".to_string()],
            cwd: "/tmp".to_string(),
            runas: "root".to_string(),
            uid: 1001,
            agent_user: "agent".to_string(),
            harness: Some("codex".to_string()),
            workspace: "/tmp".to_string(),
            summary: "agent wants sudo whoami".to_string(),
            categories: vec!["sudo.exec".to_string()],
            ttl_offer: Some(("sudo.exec".to_string(), 15)),
        }
    }

    #[test]
    fn seal_round_trips_body_and_uses_fresh_nonce() {
        let body = body();

        let (ciphertext_a, key_a) = seal(&body).expect("seal first envelope");
        let (ciphertext_b, key_b) = seal(&body).expect("seal second envelope");

        assert_ne!(ciphertext_a, ciphertext_b);
        assert_ne!(key_a, key_b);
        assert_eq!(
            open(&ciphertext_a, &key_a).expect("open first envelope"),
            body
        );
        assert_eq!(
            open(&ciphertext_b, &key_b).expect("open second envelope"),
            body
        );
    }
}
