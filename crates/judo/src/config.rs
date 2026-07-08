//! Daemon paths, identity, global config, declared humans, trusted workspaces.
//! Spec §4.3 (humans), §4.4 (trust), §5.4 (global file).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub fn config_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("judo")
}
pub fn state_dir() -> PathBuf {
    dirs::state_dir()
        .unwrap_or_else(|| dirs::data_local_dir().unwrap_or_else(|| PathBuf::from(".")))
        .join("judo")
}
pub fn socket_path() -> PathBuf {
    state_dir().join("judo.sock")
}
pub fn audit_path() -> PathBuf {
    state_dir().join("audit.jsonl")
}

/// Derive the WebAuthn RP id and https page origin from the relay WebSocket URL.
/// wss://host[:port]/path -> ("host", "https://host[:port]")
/// ws://host[:port]/path  -> ("host", "http://host[:port]")
pub fn rp_from_relay(relay_url: &str) -> Result<(String, String)> {
    let relay = url::Url::parse(relay_url).context("invalid relay WebSocket URL")?;
    let origin_scheme = match relay.scheme() {
        "wss" => "https",
        "ws" => "http",
        scheme => bail!("relay URL must use ws or wss, got {scheme}"),
    };
    let host = relay
        .host_str()
        .context("relay URL must include a host")?
        .to_string();
    let mut origin = format!("{origin_scheme}://{host}");
    if let Some(port) = relay.port() {
        let default_port = match origin_scheme {
            "https" => 443,
            "http" => 80,
            _ => unreachable!(),
        };
        if port != default_port {
            origin.push_str(&format!(":{port}"));
        }
    }
    Ok((host, origin))
}

/// Persisted daemon identity + operator declarations (spec §4.3, §7.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub daemon_id: String,
    /// ed25519 secret key, 32 bytes base64. ponytail: 0600 file, no OS keychain in the
    /// skeleton — add before any real deployment.
    pub ed25519_secret_b64: String,
    pub ed25519_public_b64: String,
    pub relay_url: String,
    pub humans: Vec<String>,
    pub ntfy_topic: String,
    #[serde(default)]
    pub passkeys: Vec<StoredPasskey>,
    #[serde(default)]
    pub trusted: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPasskey {
    pub label: String,
    /// serde_json of webauthn_rs::prelude::Passkey
    pub passkey_json: String,
}

impl Identity {
    pub fn path() -> PathBuf {
        config_dir().join("identity.json")
    }
    pub fn load() -> Result<Identity> {
        let p = Self::path();
        let s = std::fs::read_to_string(&p)
            .with_context(|| format!("no daemon identity at {} — run `judo init`", p.display()))?;
        Ok(serde_json::from_str(&s)?)
    }
    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(config_dir())?;
        let p = Self::path();
        std::fs::write(&p, serde_json::to_vec_pretty(self)?)?;
        set_0600(&p);
        Ok(())
    }
    pub fn is_human(&self, user: &str) -> bool {
        self.humans.iter().any(|h| h == user)
    }
}

#[cfg(unix)]
fn set_0600(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn set_0600(_p: &Path) {}

/// The trusted workspace whose judo.toml governs `cwd`, if any (spec §4.4).
/// Longest matching trusted prefix wins.
pub fn workspace_for<'a>(trusted: &'a [String], cwd: &str) -> Option<&'a String> {
    trusted
        .iter()
        .filter(|t| cwd == t.as_str() || cwd.starts_with(&format!("{t}/")))
        .max_by_key(|t| t.len())
}

pub fn global_policy_path() -> PathBuf {
    config_dir().join("judo.toml")
}
pub fn workspace_policy_path(dir: &str) -> PathBuf {
    Path::new(dir).join("judo.toml")
}

/// Load a policy file; Err carries the parse message so the daemon can drop the layer
/// whole and alert (spec §5.6).
pub fn load_policy_file(p: &Path) -> Result<crate::policy::PolicyFile, String> {
    let s = match std::fs::read_to_string(p) {
        Ok(s) => s,
        Err(_) => return Ok(Default::default()), // absent = empty layer, not an error
    };
    toml::from_str(&s).map_err(|e| format!("{}: {e}", p.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_from_relay_derives_origin_for_wss_without_port() {
        let (rp_id, origin) = rp_from_relay("wss://judo.stillard.com/daemon").unwrap();

        assert_eq!(rp_id, "judo.stillard.com");
        assert_eq!(origin, "https://judo.stillard.com");
    }

    #[test]
    fn rp_from_relay_keeps_explicit_wss_port() {
        let (rp_id, origin) = rp_from_relay("wss://judo.stillard.com:8443/daemon").unwrap();

        assert_eq!(rp_id, "judo.stillard.com");
        assert_eq!(origin, "https://judo.stillard.com:8443");
    }

    #[test]
    fn rp_from_relay_supports_ws_localhost() {
        let (rp_id, origin) = rp_from_relay("ws://127.0.0.1:8787/daemon").unwrap();

        assert_eq!(rp_id, "127.0.0.1");
        assert_eq!(origin, "http://127.0.0.1:8787");
    }
}
