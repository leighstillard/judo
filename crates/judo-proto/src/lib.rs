//! Shared message shapes: daemon⇄relay (spec §7.4) and plugin/CLI⇄daemon (local socket).

use serde::{Deserialize, Serialize};

/// daemon → relay
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum DaemonMsg {
    /// First frame after connect. Skeleton trusts the claimed key; production adds a
    /// signature challenge (spec §7.4).
    Hello { daemon_id: String, pubkey_b64: String },
    CreateEnvelope { id: String, ciphertext_b64: String, expires_unix: u64 },
    CancelEnvelope { id: String },
    Verdict { id: String, verdict: String },
    /// Reply to a PageEvent::Choice — WebAuthn request options JSON for the page.
    CeremonyOptions { id: String, corr: u64, options_json: String },
    /// Reply to PageEvent::Assertion.
    CeremonyResult { id: String, corr: u64, ok: bool, message: String },
    /// Enrollment: reply to EnrollEvent::Begin / Finish.
    EnrollOptions { session: String, corr: u64, options_json: String },
    EnrollResult { session: String, corr: u64, ok: bool, message: String },
}

/// relay → daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum RelayMsg {
    PageEvent { id: String, corr: u64, event: PageEvent },
    EnrollEvent { session: String, corr: u64, event: EnrollEvent },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PageEvent {
    Opened,
    /// "once" or "ttl"
    Choice { choice: String },
    Assertion { response_json: String, choice: String },
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnrollEvent {
    Begin { token: String },
    Finish { token: String, response_json: String },
}

/// Decrypted envelope body shown on the approval page (spec §7.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeBody {
    pub argv: Vec<String>,
    pub cwd: String,
    pub runas: String,
    pub uid: u32,
    pub agent_user: String,
    pub harness: Option<String>,
    pub workspace: String,
    pub summary: String,
    pub categories: Vec<String>,
    /// TTL grant offer: (category, minutes). None ⇒ only "approve once".
    pub ttl_offer: Option<(String, u64)>,
}

// ---- local unix socket: plugin / CLI → daemon (JSON lines, one request per connection)

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum LocalReq {
    /// From the sudo approval plugin. Blocks until a verdict.
    Request { uid: u32, cwd: String, runas: String, argv: Vec<String> },
    Pending,
    Approve { id: String },
    Deny { id: String },
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum LocalResp {
    Verdict { verdict: String, message: String },
    Pending { envelopes: Vec<PendingInfo> },
    Ok { message: String },
    Err { message: String },
    Status { info: StatusInfo },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInfo {
    pub id: String,
    pub age_secs: u64,
    pub state: String,
    pub agent_user: String,
    pub categories: Vec<String>,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub relay_connected: bool,
    pub relay_url: String,
    pub passkeys: usize,
    pub humans: Vec<String>,
    pub workspaces: Vec<WorkspaceInfo>,
    pub pending: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceInfo {
    pub dir: String,
    pub ok: bool,
    pub error: Option<String>,
}
