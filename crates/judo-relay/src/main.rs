use anyhow::{anyhow, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Path, State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use judo_proto::{DaemonMsg, EnrollEvent, PageEvent, RelayMsg};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

#[derive(Clone)]
struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    daemon_tx: RwLock<Option<mpsc::UnboundedSender<RelayMsg>>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<DaemonMsg>>>,
    envelopes: Mutex<HashMap<String, EnvelopeRecord>>,
    corr: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
struct EnvelopeRecord {
    ciphertext_b64: String,
    expires_unix: u64,
    verdict: Option<String>,
}

#[derive(Deserialize)]
struct ChoiceReq {
    choice: String,
}

#[derive(Deserialize)]
struct AssertionReq {
    response_json: Value,
    choice: String,
}

#[derive(Deserialize)]
struct EnrollBeginReq {
    token: String,
}

#[derive(Deserialize)]
struct EnrollFinishReq {
    token: String,
    response_json: Value,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut listen = "127.0.0.1:8787".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--listen" {
            listen = args
                .next()
                .ok_or_else(|| anyhow!("--listen requires an address"))?;
        }
    }

    let state = AppState {
        inner: Arc::new(Inner {
            daemon_tx: RwLock::new(None),
            pending: Mutex::new(HashMap::new()),
            envelopes: Mutex::new(HashMap::new()),
            corr: AtomicU64::new(1),
        }),
    };

    let app = Router::new()
        .route("/daemon", get(daemon_ws))
        .route("/a/:id", get(approval_page))
        .route("/api/a/:id/ciphertext", get(ciphertext))
        .route("/api/a/:id/choice", post(choice))
        .route("/api/a/:id/assertion", post(assertion))
        .route("/api/a/:id/deny", post(deny))
        .route("/enroll", get(enroll_page))
        .route("/api/enroll/begin", post(enroll_begin))
        .route("/api/enroll/finish", post(enroll_finish))
        .route("/api/debug/envelopes", get(debug_envelopes))
        .with_state(state);

    let addr: SocketAddr = listen.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("judo relay listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn daemon_ws(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| daemon_socket(state, socket))
}

async fn daemon_socket(state: AppState, socket: WebSocket) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<RelayMsg>();

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let Ok(text) = serde_json::to_string(&msg) else {
                continue;
            };
            if ws_tx.send(Message::Text(text)).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(msg)) = ws_rx.next().await {
        let Message::Text(text) = msg else {
            continue;
        };
        match serde_json::from_str::<DaemonMsg>(&text) {
            Ok(DaemonMsg::Hello { daemon_id, .. }) => {
                // ponytail: skeleton trusts the claimed daemon key. Production verifies an
                // ed25519 challenge before accepting the connection.
                println!("daemon connected: {daemon_id}");
                *state.inner.daemon_tx.write().await = Some(tx.clone());
            }
            Ok(msg) => handle_daemon_msg(&state, msg).await,
            Err(err) => eprintln!("bad daemon message: {err:#}"),
        }
    }

    *state.inner.daemon_tx.write().await = None;
    writer.abort();
}

async fn handle_daemon_msg(state: &AppState, msg: DaemonMsg) {
    match msg {
        DaemonMsg::CreateEnvelope {
            id,
            ciphertext_b64,
            expires_unix,
        } => {
            state.inner.envelopes.lock().await.insert(
                id,
                EnvelopeRecord {
                    ciphertext_b64,
                    expires_unix,
                    verdict: None,
                },
            );
        }
        DaemonMsg::CancelEnvelope { id } => {
            if let Some(env) = state.inner.envelopes.lock().await.get_mut(&id) {
                env.verdict = Some("cancelled".to_string());
            }
        }
        DaemonMsg::Verdict { id, verdict } => {
            if let Some(env) = state.inner.envelopes.lock().await.get_mut(&id) {
                env.verdict = Some(verdict);
            }
        }
        DaemonMsg::CeremonyOptions { corr, .. }
        | DaemonMsg::CeremonyResult { corr, .. }
        | DaemonMsg::EnrollOptions { corr, .. }
        | DaemonMsg::EnrollResult { corr, .. } => {
            if let Some(waiter) = state.inner.pending.lock().await.remove(&corr) {
                let _ = waiter.send(msg);
            }
        }
        DaemonMsg::Hello { .. } => {}
    }
}

async fn approval_page(Path(id): Path<String>) -> Html<String> {
    Html(APPROVAL_HTML.replace("__ID__", &id))
}

async fn enroll_page() -> Html<&'static str> {
    Html(ENROLL_HTML)
}

async fn ciphertext(Path(id): Path<String>, State(state): State<AppState>) -> Response {
    let envelopes = state.inner.envelopes.lock().await;
    match envelopes.get(&id) {
        Some(env) => Json(json!({
            "ciphertext_b64": env.ciphertext_b64,
            "expires_unix": env.expires_unix,
            "verdict": env.verdict,
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown envelope"})),
        )
            .into_response(),
    }
}

async fn choice(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<ChoiceReq>,
) -> Response {
    match ask_daemon(&state, |corr| RelayMsg::PageEvent {
        id: id.clone(),
        corr,
        event: PageEvent::Choice {
            choice: req.choice.clone(),
        },
    })
    .await
    {
        Ok(DaemonMsg::CeremonyOptions { options_json, .. }) => json_text(&options_json),
        Ok(DaemonMsg::CeremonyResult { ok, message, .. }) => {
            let status = if ok {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            };
            (status, Json(json!({ "ok": ok, "message": message }))).into_response()
        }
        Ok(_) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "unexpected daemon response"})),
        )
            .into_response(),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": err.to_string()})),
        )
            .into_response(),
    }
}

async fn assertion(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<AssertionReq>,
) -> Response {
    match ask_daemon(&state, |corr| RelayMsg::PageEvent {
        id: id.clone(),
        corr,
        event: PageEvent::Assertion {
            response_json: req.response_json.to_string(),
            choice: req.choice.clone(),
        },
    })
    .await
    {
        Ok(DaemonMsg::CeremonyResult { ok, message, .. }) => {
            Json(json!({ "ok": ok, "message": message })).into_response()
        }
        Ok(_) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "unexpected daemon response"})),
        )
            .into_response(),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": err.to_string()})),
        )
            .into_response(),
    }
}

async fn deny(Path(id): Path<String>, State(state): State<AppState>) -> Response {
    match send_daemon(
        &state,
        RelayMsg::PageEvent {
            id,
            corr: 0,
            event: PageEvent::Deny,
        },
    )
    .await
    {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": err.to_string()})),
        )
            .into_response(),
    }
}

async fn enroll_begin(State(state): State<AppState>, Json(req): Json<EnrollBeginReq>) -> Response {
    match ask_daemon(&state, |corr| RelayMsg::EnrollEvent {
        session: req.token.clone(),
        corr,
        event: EnrollEvent::Begin {
            token: req.token.clone(),
        },
    })
    .await
    {
        Ok(DaemonMsg::EnrollOptions { options_json, .. }) => json_text(&options_json),
        Ok(DaemonMsg::EnrollResult { ok, message, .. }) => {
            Json(json!({ "ok": ok, "message": message })).into_response()
        }
        Ok(_) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "unexpected daemon response"})),
        )
            .into_response(),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": err.to_string()})),
        )
            .into_response(),
    }
}

async fn enroll_finish(
    State(state): State<AppState>,
    Json(req): Json<EnrollFinishReq>,
) -> Response {
    match ask_daemon(&state, |corr| RelayMsg::EnrollEvent {
        session: req.token.clone(),
        corr,
        event: EnrollEvent::Finish {
            token: req.token.clone(),
            response_json: req.response_json.to_string(),
        },
    })
    .await
    {
        Ok(DaemonMsg::EnrollResult { ok, message, .. }) => {
            Json(json!({ "ok": ok, "message": message })).into_response()
        }
        Ok(_) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "unexpected daemon response"})),
        )
            .into_response(),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": err.to_string()})),
        )
            .into_response(),
    }
}

async fn debug_envelopes(State(state): State<AppState>) -> Json<Value> {
    Json(json!(*state.inner.envelopes.lock().await))
}

async fn ask_daemon<F>(state: &AppState, build: F) -> Result<DaemonMsg>
where
    F: FnOnce(u64) -> RelayMsg,
{
    let corr = state.inner.corr.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = oneshot::channel();
    state.inner.pending.lock().await.insert(corr, tx);
    if let Err(err) = send_daemon(state, build(corr)).await {
        state.inner.pending.lock().await.remove(&corr);
        return Err(err);
    }
    tokio::time::timeout(Duration::from_secs(20), rx)
        .await
        .map_err(|_| anyhow!("daemon response timed out"))?
        .map_err(|_| anyhow!("daemon response waiter dropped"))
}

async fn send_daemon(state: &AppState, msg: RelayMsg) -> Result<()> {
    let tx = state
        .inner
        .daemon_tx
        .read()
        .await
        .clone()
        .ok_or_else(|| anyhow!("no daemon connected"))?;
    tx.send(msg)
        .map_err(|_| anyhow!("daemon websocket writer closed"))
}

fn json_text(s: &str) -> Response {
    match serde_json::from_str::<Value>(s) {
        Ok(v) => Json(v).into_response(),
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("bad daemon json: {err}")})),
        )
            .into_response(),
    }
}

const APPROVAL_HTML: &str = r#"<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>judo approval</title>
<main>
  <pre id="summary">Loading envelope...</pre>
  <button id="once">Approve once</button>
  <button id="ttl" hidden>Approve TTL</button>
  <button id="deny">Deny</button>
  <pre id="out"></pre>
</main>
<script>
const id = "__ID__";
const out = document.getElementById("out");
function b64urlToArrayBuffer(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
}
function arrayBufferToB64url(buf) {
  const bin = String.fromCharCode(...new Uint8Array(buf));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function credentialToJson(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: arrayBufferToB64url(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: arrayBufferToB64url(r.authenticatorData),
      clientDataJSON: arrayBufferToB64url(r.clientDataJSON),
      signature: arrayBufferToB64url(r.signature),
      userHandle: r.userHandle ? arrayBufferToB64url(r.userHandle) : null
    }
  };
}
function b64ToBytes(s) {
  const bin = atob(s);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
function le32(a, i) {
  return (a[i] | (a[i + 1] << 8) | (a[i + 2] << 16) | (a[i + 3] << 24)) >>> 0;
}
function store32(out, i, v) {
  out[i] = v & 255;
  out[i + 1] = (v >>> 8) & 255;
  out[i + 2] = (v >>> 16) & 255;
  out[i + 3] = (v >>> 24) & 255;
}
function rotl(v, c) {
  return ((v << c) | (v >>> (32 - c))) >>> 0;
}
function qr(x, a, b, c, d) {
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 7);
}
const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
function chachaBlock(keyWords, nonceWords, counter) {
  const st = [...SIGMA, ...keyWords, counter, ...nonceWords];
  const x = st.slice();
  for (let i = 0; i < 10; i++) {
    qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15);
    qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) store32(out, i * 4, (x[i] + st[i]) >>> 0);
  return out;
}
function keyWords(key) {
  return Array.from({length: 8}, (_, i) => le32(key, i * 4));
}
function hchacha(key, nonce16) {
  const x = [...SIGMA, ...keyWords(key), le32(nonce16, 0), le32(nonce16, 4), le32(nonce16, 8), le32(nonce16, 12)];
  for (let i = 0; i < 10; i++) {
    qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15);
    qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14);
  }
  return [x[0], x[1], x[2], x[3], x[12], x[13], x[14], x[15]];
}
function xorStream(keyWords, nonceWords, data) {
  const out = new Uint8Array(data.length);
  for (let pos = 0, counter = 1; pos < data.length; pos += 64, counter++) {
    const block = chachaBlock(keyWords, nonceWords, counter);
    for (let i = 0; i < Math.min(64, data.length - pos); i++) out[pos + i] = data[pos + i] ^ block[i];
  }
  return out;
}
function leBig(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) + BigInt(bytes[i]);
  return n;
}
function write64(out, offset, n) {
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    out[offset + i] = Number(v & 255n);
    v >>= 8n;
  }
}
function poly1305(msg, key) {
  const rBytes = key.slice(0, 16);
  rBytes[3] &= 15; rBytes[7] &= 15; rBytes[11] &= 15; rBytes[15] &= 15;
  rBytes[4] &= 252; rBytes[8] &= 252; rBytes[12] &= 252;
  const r = leBig(rBytes);
  const s = leBig(key.slice(16, 32));
  const p = (1n << 130n) - 5n;
  let acc = 0n;
  for (let off = 0; off < msg.length; off += 16) {
    const block = msg.slice(off, Math.min(off + 16, msg.length));
    acc = ((acc + leBig(block) + (1n << BigInt(8 * block.length))) * r) % p;
  }
  let tag = (acc + s) & ((1n << 128n) - 1n);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = Number(tag & 255n);
    tag >>= 8n;
  }
  return out;
}
function macData(ciphertext) {
  const pad = (16 - (ciphertext.length % 16)) % 16;
  const out = new Uint8Array(ciphertext.length + pad + 16);
  out.set(ciphertext);
  write64(out, ciphertext.length + pad, 0);
  write64(out, ciphertext.length + pad + 8, ciphertext.length);
  return out;
}
function eq(a, b) {
  if (a.length !== b.length) return false;
  let v = 0;
  for (let i = 0; i < a.length; i++) v |= a[i] ^ b[i];
  return v === 0;
}
function decryptXChaCha(ciphertextB64, keyB64) {
  const key = b64ToBytes(keyB64);
  const sealed = b64ToBytes(ciphertextB64);
  const nonce = sealed.slice(0, 24);
  const box = sealed.slice(24);
  const ciphertext = box.slice(0, box.length - 16);
  const tag = box.slice(box.length - 16);
  const subkey = hchacha(key, nonce.slice(0, 16));
  const nonceWords = [0, le32(nonce, 16), le32(nonce, 20)];
  const polyKey = chachaBlock(subkey, nonceWords, 0).slice(0, 32);
  if (!eq(poly1305(macData(ciphertext), polyKey), tag)) throw new Error("Envelope authentication failed");
  return JSON.parse(new TextDecoder().decode(xorStream(subkey, nonceWords, ciphertext)));
}
let envelope = null;
async function decryptEnvelope() {
  const meta = await fetch(`/api/a/${id}/ciphertext`).then(r => r.json());
  envelope = decryptXChaCha(meta.ciphertext_b64, decodeURIComponent(location.hash.slice(1)));
  document.getElementById("summary").textContent =
    `${envelope.agent_user} in ${envelope.cwd} wants:\n${envelope.argv.join(" ")}\n\n` +
    `run as: ${envelope.runas}\nworkspace: ${envelope.workspace}\ncategories: ${envelope.categories.join(", ")}`;
  if (envelope.ttl_offer) {
    const ttl = document.getElementById("ttl");
    ttl.hidden = false;
    ttl.textContent = `Approve ${envelope.ttl_offer[0]} ${envelope.ttl_offer[1]} min`;
    ttl.onclick = () => approve(`ttl:${envelope.ttl_offer[0]}:${envelope.ttl_offer[1]}`).catch(e => out.textContent = e);
  }
}
async function approve(choice) {
  const options = await fetch(`/api/a/${id}/choice`, {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify({choice})
  }).then(r => r.json());
  options.publicKey.challenge = b64urlToArrayBuffer(options.publicKey.challenge);
  if (options.publicKey.allowCredentials) {
    for (const c of options.publicKey.allowCredentials) c.id = b64urlToArrayBuffer(c.id);
  }
  const cred = await navigator.credentials.get(options);
  const result = await fetch(`/api/a/${id}/assertion`, {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify({choice, response_json: credentialToJson(cred)})
  }).then(r => r.json());
  out.textContent = result.message || JSON.stringify(result);
}
document.getElementById("once").onclick = () => approve("once").catch(e => out.textContent = e);
document.getElementById("deny").onclick = async () => {
  const r = await fetch(`/api/a/${id}/deny`, {method: "POST"}).then(r => r.json());
  out.textContent = r.ok ? "Denied" : JSON.stringify(r);
};
decryptEnvelope().catch(e => out.textContent = e);
</script>"#;

const ENROLL_HTML: &str = r#"<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>judo enroll</title>
<button id="enroll">Enroll passkey</button>
<pre id="out"></pre>
<script>
const token = location.hash.slice(1);
const out = document.getElementById("out");
function b64urlToArrayBuffer(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
}
function arrayBufferToB64url(buf) {
  const bin = String.fromCharCode(...new Uint8Array(buf));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function attestationToJson(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: arrayBufferToB64url(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: arrayBufferToB64url(r.attestationObject),
      clientDataJSON: arrayBufferToB64url(r.clientDataJSON)
    }
  };
}
document.getElementById("enroll").onclick = async () => {
  const options = await fetch("/api/enroll/begin", {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify({token})
  }).then(r => r.json());
  options.publicKey.challenge = b64urlToArrayBuffer(options.publicKey.challenge);
  options.publicKey.user.id = b64urlToArrayBuffer(options.publicKey.user.id);
  if (options.publicKey.excludeCredentials) {
    for (const c of options.publicKey.excludeCredentials) c.id = b64urlToArrayBuffer(c.id);
  }
  const cred = await navigator.credentials.create(options);
  const result = await fetch("/api/enroll/finish", {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify({token, response_json: attestationToJson(cred)})
  }).then(r => r.json());
  out.textContent = result.message || JSON.stringify(result);
};
</script>"#;
