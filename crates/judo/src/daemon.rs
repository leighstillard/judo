use crate::{
    audit,
    config::{self, Identity},
    crypto,
    policy::{Engine, Level, PolicyFile},
    webauthn::WebauthnVerifier,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use judo_proto::{
    DaemonMsg, EnrollEvent, EnvelopeBody, LocalReq, LocalResp, PageEvent, PendingInfo, RelayMsg,
    StatusInfo, WorkspaceInfo,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{mpsc, oneshot, Mutex, RwLock},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use ulid::Ulid;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

#[derive(Clone)]
struct AppState {
    identity: Arc<Mutex<Identity>>,
    manager: Arc<Mutex<Manager>>,
    relay_tx: Arc<RwLock<Option<mpsc::UnboundedSender<DaemonMsg>>>>,
    relay_connected: Arc<AtomicBool>,
    webauthn: WebauthnVerifier,
    auth_states: Arc<Mutex<HashMap<(String, String), PasskeyAuthentication>>>,
    enroll_states: Arc<Mutex<HashMap<String, PasskeyRegistration>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CoalesceKey {
    digest: String,
    uid: u32,
    workspace: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvelopeState {
    Pending,
    Approved,
    Denied,
    TimedOut,
    #[allow(dead_code)]
    Cancelled,
}

impl EnvelopeState {
    fn as_str(self) -> &'static str {
        match self {
            EnvelopeState::Pending => "pending",
            EnvelopeState::Approved => "approved",
            EnvelopeState::Denied => "denied",
            EnvelopeState::TimedOut => "timed_out",
            EnvelopeState::Cancelled => "cancelled",
        }
    }
}

struct Envelope {
    id: String,
    key: CoalesceKey,
    body: EnvelopeBody,
    command: String,
    ciphertext_b64: String,
    created: Instant,
    expires_unix: u64,
    timeout_secs: u64,
    state: EnvelopeState,
    approval_available: bool,
    waiters: Vec<oneshot::Sender<LocalResp>>,
}

struct Manager {
    envelopes: HashMap<String, Envelope>,
    by_key: HashMap<CoalesceKey, String>,
    cooldowns: HashMap<CoalesceKey, Instant>,
    approval_origin: String,
}

struct CreatedEnvelope {
    id: String,
    ciphertext_b64: String,
    expires_unix: u64,
    text: String,
    link: String,
}

struct WaitPlan {
    id: String,
    timeout_secs: u64,
    receiver: oneshot::Receiver<LocalResp>,
    created: Option<CreatedEnvelope>,
}

enum StartResult {
    Immediate(LocalResp),
    Wait(WaitPlan),
}

enum ResolveOutcome {
    Approved,
    Denied,
}

impl Manager {
    fn new(relay_url: &str) -> Result<Self> {
        let (_, approval_origin) = config::rp_from_relay(relay_url)?;
        Ok(Self {
            envelopes: HashMap::new(),
            by_key: HashMap::new(),
            cooldowns: HashMap::new(),
            approval_origin,
        })
    }

    fn begin_approval(
        &mut self,
        key: CoalesceKey,
        body: EnvelopeBody,
        command: String,
        timeout_secs: u64,
    ) -> Result<StartResult> {
        self.cooldowns.retain(|_, until| *until > Instant::now());
        if self.cooldowns.contains_key(&key) {
            return Ok(StartResult::Immediate(LocalResp::Verdict {
                verdict: "deny".to_string(),
                message: "denied by approver — do not retry; the human explicitly rejected this."
                    .to_string(),
            }));
        }

        if let Some(id) = self.by_key.get(&key).cloned() {
            if let Some(env) = self.envelopes.get_mut(&id) {
                if env.state == EnvelopeState::Approved && env.approval_available {
                    env.approval_available = false;
                    self.by_key.remove(&key);
                    return Ok(StartResult::Immediate(LocalResp::Verdict {
                        verdict: "allow".to_string(),
                        message: "approved earlier; proceeding".to_string(),
                    }));
                }

                let (tx, rx) = oneshot::channel();
                env.waiters.push(tx);
                return Ok(StartResult::Wait(WaitPlan {
                    id,
                    timeout_secs: env.timeout_secs,
                    receiver: rx,
                    created: None,
                }));
            }
        }

        let id = Ulid::new().to_string();
        let (ciphertext_b64, fragment_key_b64) = crypto::seal(&body)?;
        let now = now_unix();
        let expires_unix = now + timeout_secs;
        let link = format!("{}/a/{id}#{fragment_key_b64}", self.approval_origin);
        let text = format!("judo approval: {}\n{}", body.summary, link);
        let (tx, rx) = oneshot::channel();

        let env = Envelope {
            id: id.clone(),
            key: key.clone(),
            body,
            command,
            ciphertext_b64: ciphertext_b64.clone(),
            created: Instant::now(),
            expires_unix,
            timeout_secs,
            state: EnvelopeState::Pending,
            approval_available: false,
            waiters: vec![tx],
        };

        self.by_key.insert(key, id.clone());
        self.envelopes.insert(id.clone(), env);

        Ok(StartResult::Wait(WaitPlan {
            id: id.clone(),
            timeout_secs,
            receiver: rx,
            created: Some(CreatedEnvelope {
                id,
                ciphertext_b64,
                expires_unix,
                text,
                link,
            }),
        }))
    }

    fn resolve(
        &mut self,
        id: &str,
        outcome: ResolveOutcome,
        approver: &str,
        cooldown_secs: u64,
    ) -> Result<String> {
        let env = self
            .envelopes
            .get_mut(id)
            .ok_or_else(|| anyhow!("unknown envelope {id}"))?;

        match outcome {
            ResolveOutcome::Approved => {
                env.state = EnvelopeState::Approved;
                let waiters = std::mem::take(&mut env.waiters);
                if waiters.is_empty() {
                    env.approval_available = true;
                } else {
                    env.approval_available = false;
                    self.by_key.remove(&env.key);
                    for waiter in waiters {
                        let _ = waiter.send(LocalResp::Verdict {
                            verdict: "allow".to_string(),
                            message: format!("approved by {approver}; proceeding"),
                        });
                    }
                }
                Ok("approved".to_string())
            }
            ResolveOutcome::Denied => {
                env.state = EnvelopeState::Denied;
                self.by_key.remove(&env.key);
                self.cooldowns.insert(
                    env.key.clone(),
                    Instant::now() + Duration::from_secs(cooldown_secs),
                );
                for waiter in std::mem::take(&mut env.waiters) {
                    let _ = waiter.send(LocalResp::Verdict {
                        verdict: "deny".to_string(),
                        message: format!(
                            "denied by {approver} — do not retry; the human explicitly rejected this."
                        ),
                    });
                }
                Ok("denied".to_string())
            }
        }
    }

    fn mark_timed_out(&mut self, id: &str) {
        if let Some(env) = self.envelopes.get_mut(id) {
            if env.state == EnvelopeState::Pending {
                env.state = EnvelopeState::TimedOut;
            }
        }
    }

    fn pending(&self) -> Vec<PendingInfo> {
        self.envelopes
            .values()
            .filter(|e| matches!(e.state, EnvelopeState::Pending | EnvelopeState::TimedOut))
            .map(|e| PendingInfo {
                id: e.id.clone(),
                age_secs: e.created.elapsed().as_secs(),
                state: e.state.as_str().to_string(),
                agent_user: e.body.agent_user.clone(),
                categories: e.body.categories.clone(),
                command: e.command.clone(),
            })
            .collect()
    }

    fn replayable(&self) -> Vec<DaemonMsg> {
        self.envelopes
            .values()
            .filter(|e| matches!(e.state, EnvelopeState::Pending | EnvelopeState::TimedOut))
            .map(|e| DaemonMsg::CreateEnvelope {
                id: e.id.clone(),
                ciphertext_b64: e.ciphertext_b64.clone(),
                expires_unix: e.expires_unix,
            })
            .collect()
    }
}

pub async fn run() -> Result<()> {
    let identity = Identity::load()?;
    run_with_identity(identity).await
}

pub async fn run_with_identity(identity: Identity) -> Result<()> {
    let webauthn = WebauthnVerifier::new(&identity.relay_url)?;
    let manager = Manager::new(&identity.relay_url)?;
    let state = AppState {
        identity: Arc::new(Mutex::new(identity)),
        manager: Arc::new(Mutex::new(manager)),
        relay_tx: Arc::new(RwLock::new(None)),
        relay_connected: Arc::new(AtomicBool::new(false)),
        webauthn,
        auth_states: Arc::new(Mutex::new(HashMap::new())),
        enroll_states: Arc::new(Mutex::new(HashMap::new())),
    };

    tokio::spawn(relay_loop(state.clone()));
    local_socket_loop(state).await
}

async fn local_socket_loop(state: AppState) -> Result<()> {
    let socket_path = config::socket_path();
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        fs::remove_file(&socket_path)
            .with_context(|| format!("failed to remove stale socket {}", socket_path.display()))?;
    }

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind {}", socket_path.display()))?;
    println!("judo daemon listening on {}", socket_path.display());

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_local_conn(state, stream).await {
                eprintln!("local request failed: {err:#}");
            }
        });
    }
}

async fn handle_local_conn(state: AppState, mut stream: UnixStream) -> Result<()> {
    let peer_uid = stream.peer_cred().ok().map(|c| c.uid());
    let peer_pid = stream
        .peer_cred()
        .ok()
        .and_then(|c| c.pid().map(|pid| pid as u32));
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&mut stream);
        reader.read_line(&mut line).await?;
    }
    let req: LocalReq = serde_json::from_str(line.trim())?;
    let resp = handle_local_req(state, req, peer_uid, peer_pid).await;
    let resp = match resp {
        Ok(resp) => resp,
        Err(err) => LocalResp::Err {
            message: format!("{err:#}"),
        },
    };
    stream
        .write_all(serde_json::to_string(&resp)?.as_bytes())
        .await?;
    stream.write_all(b"\n").await?;
    Ok(())
}

async fn handle_local_req(
    state: AppState,
    req: LocalReq,
    peer_uid: Option<u32>,
    peer_pid: Option<u32>,
) -> Result<LocalResp> {
    match req {
        LocalReq::Request {
            uid,
            cwd,
            runas,
            argv,
        } => handle_approval_request(state, uid, cwd, runas, argv, peer_pid).await,
        LocalReq::Pending => {
            require_human_peer(&state, peer_uid).await?;
            Ok(LocalResp::Pending {
                envelopes: state.manager.lock().await.pending(),
            })
        }
        LocalReq::Approve { id } => {
            let approver = require_human_peer(&state, peer_uid).await?;
            let identity = state.identity.lock().await.clone();
            let cooldown = engine_for(&identity, None).1.cooldown_secs();
            state.manager.lock().await.resolve(
                &id,
                ResolveOutcome::Approved,
                &approver,
                cooldown,
            )?;
            audit::audit(
                "envelope.approved",
                json!({ "id": id, "source": "local-cli" }),
            )?;
            send_relay(
                &state,
                DaemonMsg::Verdict {
                    id,
                    verdict: "approved".to_string(),
                },
            )
            .await;
            Ok(LocalResp::Ok {
                message: "approved".to_string(),
            })
        }
        LocalReq::Deny { id } => {
            let approver = require_human_peer(&state, peer_uid).await?;
            let identity = state.identity.lock().await.clone();
            let cooldown = engine_for(&identity, None).1.cooldown_secs();
            state
                .manager
                .lock()
                .await
                .resolve(&id, ResolveOutcome::Denied, &approver, cooldown)?;
            audit::audit(
                "envelope.denied",
                json!({ "id": id, "source": "local-cli" }),
            )?;
            send_relay(
                &state,
                DaemonMsg::Verdict {
                    id,
                    verdict: "denied".to_string(),
                },
            )
            .await;
            Ok(LocalResp::Ok {
                message: "denied".to_string(),
            })
        }
        LocalReq::Status => {
            require_human_peer(&state, peer_uid).await?;
            status(&state).await
        }
    }
}

async fn handle_approval_request(
    state: AppState,
    uid: u32,
    cwd: String,
    runas: String,
    argv: Vec<String>,
    peer_pid: Option<u32>,
) -> Result<LocalResp> {
    let identity = state.identity.lock().await.clone();
    let agent_user = username_for_uid(uid).unwrap_or_else(|| format!("uid-{uid}"));
    if identity.is_human(&agent_user) {
        return Ok(LocalResp::Verdict {
            verdict: "allow".to_string(),
            message: "declared human bypass".to_string(),
        });
    }

    let workspace = config::workspace_for(&identity.trusted, &cwd)
        .cloned()
        .unwrap_or_else(|| cwd.clone());
    let (workspace_policy, engine) = engine_for(&identity, Some(&workspace));
    let harness = sniff_harness(peer_pid);
    let raw = shell_join(&argv);
    let decision = engine.classify(
        &raw,
        &agent_user,
        harness.as_deref(),
        targets_policy_file(&argv, &cwd, &workspace),
    );
    let summary = format!("{} in {} wants `{}`", agent_user, cwd, raw);
    let body = EnvelopeBody {
        argv: argv.clone(),
        cwd: cwd.clone(),
        runas,
        uid,
        agent_user: agent_user.clone(),
        harness: harness.clone(),
        workspace: workspace.clone(),
        summary: summary.clone(),
        categories: if let Some(hardline) = &decision.hardline {
            vec![hardline.clone()]
        } else {
            decision.categories()
        },
        ttl_offer: decision.ttl_offer(),
    };
    let effective = decision.effective();

    audit::audit(
        "request.classified",
        json!({
            "uid": uid,
            "agent_user": agent_user,
            "workspace": workspace.clone(),
            "command": raw.clone(),
            "effective": effective.as_str(),
            "categories": body.categories.clone(),
            "workspace_policy_loaded": workspace_policy,
        }),
    )?;

    match effective {
        Level::Allow => Ok(LocalResp::Verdict {
            verdict: "allow".to_string(),
            message: "allowed by policy".to_string(),
        }),
        Level::Notify => {
            // ponytail: notify delivery is logged for the skeleton; production retries and
            // reports channel-specific failures.
            println!("judo notify: {summary}");
            Ok(LocalResp::Verdict {
                verdict: "allow".to_string(),
                message: "allowed by policy; notification sent".to_string(),
            })
        }
        Level::Deny => Ok(LocalResp::Verdict {
            verdict: "deny".to_string(),
            message: "denied by policy".to_string(),
        }),
        Level::Approve => {
            let key = CoalesceKey {
                digest: digest_command(&decision.normalized),
                uid,
                workspace,
            };
            let start =
                state
                    .manager
                    .lock()
                    .await
                    .begin_approval(key, body, raw, engine.timeout_secs())?;

            let wait = match start {
                StartResult::Immediate(resp) => return Ok(resp),
                StartResult::Wait(wait) => wait,
            };

            if let Some(created) = &wait.created {
                audit::audit(
                    "envelope.created",
                    json!({ "id": created.id, "expires_unix": created.expires_unix }),
                )?;
                send_relay(
                    &state,
                    DaemonMsg::CreateEnvelope {
                        id: created.id.clone(),
                        ciphertext_b64: created.ciphertext_b64.clone(),
                        expires_unix: created.expires_unix,
                    },
                )
                .await;
                notify(&identity, &created.text, &created.link).await;
            }

            match tokio::time::timeout(Duration::from_secs(wait.timeout_secs), wait.receiver).await
            {
                Ok(Ok(resp)) => Ok(resp),
                Ok(Err(_)) => Ok(LocalResp::Err {
                    message: "approval waiter was dropped".to_string(),
                }),
                Err(_) => {
                    state.manager.lock().await.mark_timed_out(&wait.id);
                    audit::audit("envelope.timed_out", json!({ "id": wait.id }))?;
                    send_relay(
                        &state,
                        DaemonMsg::Verdict {
                            id: wait.id,
                            verdict: "timed_out".to_string(),
                        },
                    )
                    .await;
                    Ok(LocalResp::Verdict {
                        verdict: "timeout".to_string(),
                        message: "approval timed out — the human was unavailable; the request remains visible in `judo pending`; you may retry later.".to_string(),
                    })
                }
            }
        }
    }
}

async fn status(state: &AppState) -> Result<LocalResp> {
    let identity = state.identity.lock().await.clone();
    let mut workspaces = Vec::new();
    for dir in &identity.trusted {
        let path = config::workspace_policy_path(dir);
        match config::load_policy_file(&path) {
            Ok(_) => workspaces.push(WorkspaceInfo {
                dir: dir.clone(),
                ok: true,
                error: None,
            }),
            Err(error) => workspaces.push(WorkspaceInfo {
                dir: dir.clone(),
                ok: false,
                error: Some(error),
            }),
        }
    }

    Ok(LocalResp::Status {
        info: StatusInfo {
            relay_connected: state.relay_connected.load(Ordering::Relaxed),
            relay_url: identity.relay_url,
            passkeys: identity.passkeys.len(),
            humans: identity.humans,
            workspaces,
            pending: state.manager.lock().await.pending().len(),
        },
    })
}

async fn require_human_peer(state: &AppState, peer_uid: Option<u32>) -> Result<String> {
    let uid = peer_uid.ok_or_else(|| anyhow!("missing SO_PEERCRED uid"))?;
    let user = username_for_uid(uid).ok_or_else(|| anyhow!("unknown peer uid {uid}"))?;
    if state.identity.lock().await.is_human(&user) {
        Ok(user)
    } else {
        Err(anyhow!("local approval verbs require a declared human uid"))
    }
}

async fn relay_loop(state: AppState) {
    loop {
        if let Err(err) = relay_once(state.clone()).await {
            state.relay_connected.store(false, Ordering::Relaxed);
            *state.relay_tx.write().await = None;
            eprintln!("relay disconnected: {err:#}");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

async fn relay_once(state: AppState) -> Result<()> {
    let identity = state.identity.lock().await.clone();
    let (ws, _) = connect_async(&identity.relay_url)
        .await
        .with_context(|| format!("failed to connect relay {}", identity.relay_url))?;
    let (mut write, mut read) = ws.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<DaemonMsg>();
    *state.relay_tx.write().await = Some(tx.clone());
    state.relay_connected.store(true, Ordering::Relaxed);

    tx.send(DaemonMsg::Hello {
        daemon_id: identity.daemon_id,
        pubkey_b64: identity.ed25519_public_b64,
    })?;
    for msg in state.manager.lock().await.replayable() {
        tx.send(msg)?;
    }

    loop {
        tokio::select! {
            Some(msg) = rx.recv() => {
                write.send(Message::Text(serde_json::to_string(&msg)?)).await?;
            }
            incoming = read.next() => {
                let Some(incoming) = incoming else { break; };
                let incoming = incoming?;
                if let Message::Text(text) = incoming {
                    let msg: RelayMsg = serde_json::from_str(&text)?;
                    handle_relay_msg(&state, msg).await?;
                }
            }
        }
    }

    Err(anyhow!("relay websocket closed"))
}

async fn handle_relay_msg(state: &AppState, msg: RelayMsg) -> Result<()> {
    match msg {
        RelayMsg::PageEvent { id, corr, event } => match event {
            PageEvent::Opened => {
                audit::audit("page.opened", json!({ "id": id }))?;
            }
            PageEvent::Choice { choice } => {
                let identity = state.identity.lock().await.clone();
                match state.webauthn.start_authentication(&identity) {
                    Ok((options_json, auth_state)) => {
                        state
                            .auth_states
                            .lock()
                            .await
                            .insert((id.clone(), choice), auth_state);
                        send_relay(
                            state,
                            DaemonMsg::CeremonyOptions {
                                id,
                                corr,
                                options_json,
                            },
                        )
                        .await;
                    }
                    Err(err) => {
                        send_relay(
                            state,
                            DaemonMsg::CeremonyResult {
                                id,
                                corr,
                                ok: false,
                                message: format!("{err:#}"),
                            },
                        )
                        .await;
                    }
                }
            }
            PageEvent::Assertion {
                response_json,
                choice,
            } => {
                let auth_state = state.auth_states.lock().await.remove(&(id.clone(), choice));
                let result = if let Some(auth_state) = auth_state {
                    state
                        .webauthn
                        .finish_authentication(&response_json, &auth_state)
                } else {
                    Err(anyhow!("unknown or already-used ceremony"))
                };
                match result {
                    Ok(()) => {
                        let identity = state.identity.lock().await.clone();
                        let cooldown = engine_for(&identity, None).1.cooldown_secs();
                        state.manager.lock().await.resolve(
                            &id,
                            ResolveOutcome::Approved,
                            "passkey",
                            cooldown,
                        )?;
                        audit::audit(
                            "envelope.approved",
                            json!({ "id": id, "source": "passkey" }),
                        )?;
                        send_relay(
                            state,
                            DaemonMsg::CeremonyResult {
                                id: id.clone(),
                                corr,
                                ok: true,
                                message: "approved".to_string(),
                            },
                        )
                        .await;
                        send_relay(
                            state,
                            DaemonMsg::Verdict {
                                id,
                                verdict: "approved".to_string(),
                            },
                        )
                        .await;
                    }
                    Err(err) => {
                        send_relay(
                            state,
                            DaemonMsg::CeremonyResult {
                                id,
                                corr,
                                ok: false,
                                message: format!("{err:#}"),
                            },
                        )
                        .await;
                    }
                }
            }
            PageEvent::Deny => {
                let identity = state.identity.lock().await.clone();
                let cooldown = engine_for(&identity, None).1.cooldown_secs();
                state.manager.lock().await.resolve(
                    &id,
                    ResolveOutcome::Denied,
                    "link",
                    cooldown,
                )?;
                audit::audit("envelope.denied", json!({ "id": id, "source": "link" }))?;
                send_relay(
                    state,
                    DaemonMsg::Verdict {
                        id,
                        verdict: "denied".to_string(),
                    },
                )
                .await;
            }
        },
        RelayMsg::EnrollEvent {
            session,
            corr,
            event,
        } => match event {
            EnrollEvent::Begin { token } => {
                let user = state
                    .identity
                    .lock()
                    .await
                    .humans
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "judo-human".to_string());
                let (options_json, reg_state) = state.webauthn.start_registration(&user)?;
                state.enroll_states.lock().await.insert(token, reg_state);
                send_relay(
                    state,
                    DaemonMsg::EnrollOptions {
                        session,
                        corr,
                        options_json,
                    },
                )
                .await;
            }
            EnrollEvent::Finish {
                token,
                response_json,
            } => {
                let reg_state = state.enroll_states.lock().await.remove(&token);
                let result = if let Some(reg_state) = reg_state {
                    state
                        .webauthn
                        .finish_registration(&response_json, &reg_state, "passkey")
                } else {
                    Err(anyhow!("unknown or already-used enrollment ceremony"))
                };
                match result {
                    Ok(passkey) => {
                        let mut identity = state.identity.lock().await;
                        identity.passkeys.push(passkey);
                        identity.save()?;
                        send_relay(
                            state,
                            DaemonMsg::EnrollResult {
                                session,
                                corr,
                                ok: true,
                                message: "passkey enrolled".to_string(),
                            },
                        )
                        .await;
                    }
                    Err(err) => {
                        send_relay(
                            state,
                            DaemonMsg::EnrollResult {
                                session,
                                corr,
                                ok: false,
                                message: format!("{err:#}"),
                            },
                        )
                        .await;
                    }
                }
            }
        },
    }
    Ok(())
}

async fn send_relay(state: &AppState, msg: DaemonMsg) {
    if let Some(tx) = state.relay_tx.read().await.as_ref() {
        let _ = tx.send(msg);
    }
}

async fn notify(identity: &Identity, text: &str, link: &str) {
    // ponytail: the skeleton logs the push so the headless smoke needs no external ntfy
    // service. Production plugs in the §11 channel trait and retries delivery failures.
    println!("judo push [{}]: {}\n{}", identity.ntfy_topic, text, link);
    let _ = audit::audit(
        "notification.sent",
        json!({ "topic": identity.ntfy_topic, "link": link }),
    );
}

fn engine_for(identity: &Identity, workspace: Option<&str>) -> (bool, Engine) {
    let global = load_policy_layer(&config::global_policy_path()).unwrap_or_default();
    let workspace_file = workspace
        .map(config::workspace_policy_path)
        .and_then(|p| load_policy_layer(&p));
    let workspace_loaded = workspace_file.is_some();
    let workspace = workspace_file.unwrap_or_default();
    let _ = identity; // kept explicit: future channel alerts use identity here.
    (workspace_loaded, Engine::new(global, workspace))
}

fn load_policy_layer(path: &Path) -> Option<PolicyFile> {
    match config::load_policy_file(path) {
        Ok(policy) => Some(policy),
        Err(error) => {
            let _ = audit::audit(
                "policy.layer_dropped",
                json!({ "path": path.display().to_string(), "error": error }),
            );
            eprintln!("judo policy layer dropped: {error}");
            None
        }
    }
}

fn targets_policy_file(argv: &[String], cwd: &str, workspace: &str) -> bool {
    let protected = [
        config::global_policy_path(),
        config::workspace_policy_path(workspace),
        Identity::path(),
    ];
    argv.iter().any(|arg| {
        let candidate = if arg.starts_with('/') {
            Path::new(arg).to_path_buf()
        } else {
            Path::new(cwd).join(arg)
        };
        arg.contains("judo.toml") || protected.iter().any(|p| &candidate == p)
    })
}

fn digest_command(normalized: &str) -> String {
    STANDARD.encode(Sha256::digest(normalized.as_bytes()))
}

fn shell_join(argv: &[String]) -> String {
    argv.join(" ")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn username_for_uid(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut parts = line.split(':');
        let name = parts.next()?;
        let _passwd = parts.next()?;
        let found_uid = parts.next()?.parse::<u32>().ok()?;
        (found_uid == uid).then(|| name.to_string())
    })
}

fn sniff_harness(peer_pid: Option<u32>) -> Option<String> {
    let mut pid = peer_pid?;
    for _ in 0..12 {
        let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        let environ = fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
        let haystack = format!(
            "{}\n{}",
            comm.to_lowercase(),
            String::from_utf8_lossy(&environ).to_lowercase()
        );
        if haystack.contains("claudecode") || haystack.contains("claude") {
            return Some("claude-code".to_string());
        }
        if haystack.contains("codex") {
            return Some("codex".to_string());
        }
        let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let ppid = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|s| s.trim().parse::<u32>().ok())?;
        if ppid == 0 || ppid == pid {
            break;
        }
        pid = ppid;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coalesce_key() -> CoalesceKey {
        CoalesceKey {
            digest: "digest".to_string(),
            uid: 1001,
            workspace: "/tmp".to_string(),
        }
    }

    fn envelope_body() -> EnvelopeBody {
        EnvelopeBody {
            argv: vec!["echo".to_string(), "hi".to_string()],
            cwd: "/tmp".to_string(),
            runas: "root".to_string(),
            uid: 1001,
            agent_user: "agent".to_string(),
            harness: None,
            workspace: "/tmp".to_string(),
            summary: "agent wants echo hi".to_string(),
            categories: vec!["sudo.exec".to_string()],
            ttl_offer: None,
        }
    }

    #[test]
    fn approval_link_uses_origin_from_relay_url() {
        let mut manager = Manager::new("wss://judo.stillard.com/daemon").unwrap();
        let result = manager
            .begin_approval(coalesce_key(), envelope_body(), "echo hi".to_string(), 30)
            .expect("begin approval");
        let StartResult::Wait(plan) = result else {
            panic!("expected wait plan");
        };
        let created = plan.created.expect("created envelope");

        assert!(created.link.starts_with("https://judo.stillard.com/a/"));
    }
}
