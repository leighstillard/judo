use crate::{
    config::{self, Identity},
    daemon,
    policy::Engine,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use judo_proto::{LocalReq, LocalResp};
use qrcode::{render::unicode, QrCode};
use rand::{rngs::OsRng, RngCore};
use std::{
    io::{self, Write},
    path::PathBuf,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

#[derive(Parser)]
#[command(name = "judo", about = "passkey privilege broker for AI agents")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init,
    Trust {
        dir: PathBuf,
    },
    Untrust {
        dir: PathBuf,
    },
    Daemon,
    Status,
    Pending,
    Approve {
        id: String,
    },
    Deny {
        id: String,
    },
    Classify {
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        harness: Option<String>,
        #[arg(required = true, last = true)]
        cmd: Vec<String>,
    },
    Run {
        #[arg(required = true, last = true)]
        cmd: Vec<String>,
    },
}

pub async fn run() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Init => init(),
        Command::Trust { dir } => trust(dir),
        Command::Untrust { dir } => untrust(dir),
        Command::Daemon => daemon::run().await,
        Command::Status => print_status().await,
        Command::Pending => print_pending().await,
        Command::Approve { id } => print_simple(send_local(LocalReq::Approve { id }).await?),
        Command::Deny { id } => print_simple(send_local(LocalReq::Deny { id }).await?),
        Command::Classify {
            agent,
            harness,
            cmd,
        } => classify(agent, harness, cmd),
        Command::Run { cmd } => brokered_run(cmd).await,
    }
}

fn init() -> Result<()> {
    let mut rng = OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();
    let daemon_id = ulid::Ulid::new().to_string();
    let default_user = std::env::var("USER").unwrap_or_else(|_| "human".to_string());
    let humans = prompt("Declared human login(s), comma separated", &default_user)?;
    let relay_url = prompt("Relay WebSocket URL", "ws://127.0.0.1:8787/daemon")?;
    let ntfy_topic = prompt("ntfy topic (use 'log' for local smoke)", "log")?;

    let mut enroll_key = [0u8; 32];
    rng.fill_bytes(&mut enroll_key);
    let (_, origin) = config::rp_from_relay(&relay_url)?;
    let enroll_url = format!("{origin}/enroll#{}", STANDARD.encode(enroll_key));
    let code = QrCode::new(enroll_url.as_bytes())?;
    println!("{}", code.render::<unicode::Dense1x2>().build());
    println!("Enroll first passkey: {enroll_url}");
    // ponytail: init prints the enrollment QR and saves the daemon identity. The full
    // first-passkey ceremony runs through the daemon+relay enrollment endpoints once
    // the daemon is started; production init should block until that ceremony finishes.

    let identity = Identity {
        daemon_id,
        ed25519_secret_b64: STANDARD.encode(signing.to_bytes()),
        ed25519_public_b64: STANDARD.encode(verifying.to_bytes()),
        relay_url,
        humans: humans
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        ntfy_topic,
        passkeys: Vec::new(),
        trusted: Vec::new(),
    };
    identity.save()?;
    println!("saved {}", Identity::path().display());
    Ok(())
}

fn trust(dir: PathBuf) -> Result<()> {
    let dir = dir.canonicalize()?;
    let dir_s = dir.to_string_lossy().to_string();
    let policy_path = config::workspace_policy_path(&dir_s);
    if let Err(error) = config::load_policy_file(&policy_path) {
        return Err(anyhow!("refusing to trust malformed policy: {error}"));
    }

    let mut identity = Identity::load()?;
    if !identity.trusted.iter().any(|d| d == &dir_s) {
        identity.trusted.push(dir_s.clone());
        identity.trusted.sort();
        identity.save()?;
    }
    println!("trusted {dir_s}");
    Ok(())
}

fn untrust(dir: PathBuf) -> Result<()> {
    let dir = dir.canonicalize()?;
    let dir_s = dir.to_string_lossy().to_string();
    let mut identity = Identity::load()?;
    identity.trusted.retain(|d| d != &dir_s);
    identity.save()?;
    println!("untrusted {dir_s}");
    Ok(())
}

async fn print_status() -> Result<()> {
    match send_local(LocalReq::Status).await? {
        LocalResp::Status { info } => {
            println!(
                "relay: {} ({})",
                info.relay_url,
                if info.relay_connected {
                    "connected"
                } else {
                    "disconnected"
                }
            );
            println!("humans: {}", info.humans.join(", "));
            println!("passkeys: {}", info.passkeys);
            println!("pending: {}", info.pending);
            for ws in info.workspaces {
                if ws.ok {
                    println!("workspace: {} ok", ws.dir);
                } else {
                    println!(
                        "workspace: {} dropped: {}",
                        ws.dir,
                        ws.error.unwrap_or_else(|| "unknown error".to_string())
                    );
                }
            }
            Ok(())
        }
        other => print_simple(other),
    }
}

async fn print_pending() -> Result<()> {
    match send_local(LocalReq::Pending).await? {
        LocalResp::Pending { envelopes } => {
            for e in envelopes {
                println!(
                    "{} [{}] {}s {} {}",
                    e.id, e.state, e.age_secs, e.agent_user, e.command
                );
            }
            Ok(())
        }
        other => print_simple(other),
    }
}

fn classify(agent: Option<String>, harness: Option<String>, cmd: Vec<String>) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let cwd_s = cwd.to_string_lossy().to_string();
    let identity = Identity::load().ok();
    let workspace = identity
        .as_ref()
        .and_then(|i| config::workspace_for(&i.trusted, &cwd_s).cloned());
    let global = load_policy_or_default(config::global_policy_path());
    let workspace_policy = workspace
        .as_ref()
        .map(|w| load_policy_or_default(config::workspace_policy_path(w)))
        .unwrap_or_default();
    let engine = Engine::new(global, workspace_policy);
    let agent = agent
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "agent".to_string());
    let raw = cmd.join(" ");
    let decision = engine.classify(&raw, &agent, harness.as_deref(), false);

    println!("normalized: {}", decision.normalized);
    if let Some(hardline) = &decision.hardline {
        println!("match: {hardline} deny builtin-hardline");
    }
    for hit in &decision.hits {
        println!(
            "match: {} {} {}",
            hit.category,
            hit.level.as_str(),
            hit.source
        );
    }
    println!("effective: {}", decision.effective().as_str());
    match decision.ttl_offer() {
        Some((category, mins)) => {
            println!("approver: passkey required; ttl offered {category} {mins}m")
        }
        None if decision.effective().as_str() == "approve" => {
            println!("approver: passkey required; approve-once only")
        }
        None => println!("approver: none"),
    }
    Ok(())
}

async fn brokered_run(cmd: Vec<String>) -> Result<()> {
    let cwd = std::env::current_dir()?.to_string_lossy().to_string();
    let uid = unsafe { libc::geteuid() as u32 };
    match send_local(LocalReq::Request {
        uid,
        cwd,
        runas: "root".to_string(),
        argv: cmd.clone(),
    })
    .await?
    {
        LocalResp::Verdict { verdict, message } if verdict == "allow" => {
            eprintln!("{message}");
            exec_cmd(cmd)
        }
        LocalResp::Verdict { message, .. } => Err(anyhow!("{message}")),
        LocalResp::Err { message } => Err(anyhow!("{message}")),
        other => Err(anyhow!("unexpected daemon response: {other:?}")),
    }
}

async fn send_local(req: LocalReq) -> Result<LocalResp> {
    let mut stream = UnixStream::connect(config::socket_path())
        .await
        .with_context(|| format!("failed to connect {}", config::socket_path().display()))?;
    stream
        .write_all(serde_json::to_string(&req)?.as_bytes())
        .await?;
    stream.write_all(b"\n").await?;
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line).await?;
    Ok(serde_json::from_str(line.trim())?)
}

fn print_simple(resp: LocalResp) -> Result<()> {
    match resp {
        LocalResp::Ok { message }
        | LocalResp::Err { message }
        | LocalResp::Verdict { message, .. } => println!("{message}"),
        other => println!("{other:?}"),
    }
    Ok(())
}

fn prompt(label: &str, default: &str) -> Result<String> {
    print!("{label} [{default}]: ");
    io::stdout().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    let s = s.trim();
    if s.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(s.to_string())
    }
}

fn load_policy_or_default(path: PathBuf) -> crate::policy::PolicyFile {
    match config::load_policy_file(&path) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("dropped policy layer: {error}");
            Default::default()
        }
    }
}

#[cfg(unix)]
fn exec_cmd(cmd: Vec<String>) -> Result<()> {
    use std::os::unix::process::CommandExt;
    if cmd.is_empty() {
        return Err(anyhow!("empty command"));
    }
    let err = std::process::Command::new(&cmd[0]).args(&cmd[1..]).exec();
    Err(anyhow!(err))
}

#[cfg(not(unix))]
fn exec_cmd(_cmd: Vec<String>) -> Result<()> {
    Err(anyhow!("judo run is only implemented on unix"))
}
