# judo — design spec

judo is a **passkey privilege broker for AI agents**. Agents get privileged or dangerous
commands (`sudo`, cloud changes, table drops) only through a human approval: a push
notification carries a link, the human approves with a passkey (WebAuthn) on their phone,
and the command proceeds. No passwords, no standing credentials in agent reach.

This spec consolidates every decision from the
[wayfinder map](https://github.com/leighstillard/judo/issues/1). It is **buildable**: a
fresh implementation session should find no open design questions. Deep rationale lives
in the linked tickets and `docs/research/`; this document states what to build.

- Resolves [#10](https://github.com/leighstillard/judo/issues/10).
- Companion deliverable: the [walking skeleton](https://github.com/leighstillard/judo/issues/11) (§13).

---

## 1. The broker model

judo is a **real broker, not a cooperative wrapper**: it holds the privilege, and agents
structurally cannot route around it. For sudo, the agent's Unix user has no password and
no NOPASSWD — authentication succeeds only on the judo daemon's say-so. This is the
defining contrast with Hermes-style in-process gating, where the guard lives in the
agent's own address space and survives only as long as the agent cooperates
([Hermes research](research/hermes-approval-subsystem.md)).

Primary agent surface is **transparent interception** (sudo plugin / PAM,
`credential_process`, …): the agent types `sudo systemctl restart api` like anyone else
and judo intervenes. `judo run <cmd>` exists as an explicit fallback for privilege
points without a shim (§10).

## 2. Threat model

**Trusted:** the daemon host's root and the daemon itself; the human's
passkey authenticator (phone/security key); kernel-verified Unix identity.

**Untrusted / adversarial:**

- **The agent** — may craft commands to evade classification, spoof environment/process
  markers, `cd` into permissive directories, retry in loops, or attempt to edit policy
  files. Countered by: normalization pipeline (§5.3), tighten-only identity (§4),
  `judo trust` (§4.4), coalescing + deny cooldown (§6.3), floor-flagged `policy.write` (§5.6).
- **The relay** — honest-but-curious to actively malicious. It never sees plaintext
  envelopes (§7.1), cannot forge approvals (it holds no passkey private key), and cannot
  upgrade a grant choice (§7.2). What it *can* do: drop/delay envelopes (= deny, which is
  fail-safe) and control the approval page's pixels. The pixel problem
  ("what you see is what you sign") is mitigated in v1 by echoing the exact command in
  the notification itself; hardening path is a daemon-served page (§9.3).
- **The notification channel** — sees the approval link (including the decryption key in
  the fragment) and the command echo. Acceptable: the channel is the human's own
  configured transport, and possession of the link grants only deny (fail-safe) — approval
  still requires the passkey ceremony.

**Explicitly not defended:** an attacker with root on the daemon host (they own the
daemon), and a compromised human authenticator. Lockout safety: declared humans bypass
judo entirely (§4.3), so a dead daemon never locks the human out of their own box.

## 3. Architecture

```text
agent ── sudo ──► interception shim ──► judo daemon ──► outbound WebSocket ──► relay
                  (approval plugin /       │                                    │
                   PAM module)             │ policy engine, envelopes,          │ stores ciphertext,
                                           │ WebAuthn verifier, audit log      │ serves approval page,
                                           │                                    ▼
                                           │◄── verdict ◄── passkey ceremony ◄─ phone (ntfy push, link)
```

Components:

| Component | Runs | Language | Role |
|---|---|---|---|
| **daemon** | agent's host, per human owner | Rust, single static binary (`judo daemon`) | policy, envelopes, WebAuthn verification, audit, CLI backend |
| **interception shims** | privilege points | Python (skeleton) → Rust cdylib | sudo approval plugin; judo PAM module |
| **relay** | hosted (`judo.dev`) | Rust | content-blind ciphertext store, approval-page host, push fan-out |
| **approval page** | phone browser | static JS on `approve.judo.dev` | decrypt envelope client-side, run passkey ceremony |
| **channels** | daemon-side plugins | Rust trait impls | carry {text, link} to the human; ntfy in v1 (§11) |
| **CLI** | same binary as daemon | Rust | §10 |

Credentials and plaintext never leave the daemon host. The relay exists to provide the
stable HTTPS origin WebAuthn needs plus push reachability — nothing else.

## 4. Agent identity

Full rationale: [Agent identity](https://github.com/leighstillard/judo/issues/5).

### 4.1 Tighten-only principle

Forgeable signals (process ancestry, env markers, cwd) may only select policy **equal to
or stricter than** the workspace baseline. Loosening requires kernel-grade identity.
Spoofing a harness label buys an attacker nothing.

### 4.2 What an "agent" is

- **Unix user** (kernel-verified, from the intercepted request's uid) — the enforcement
  identity. Only `[agents.<unix-user>]` rules can relax anything.
- **Harness label** (`claude-code`, `codex`, `hermes`, …) — sniffed best-effort at
  decision time via one `/proc` walk (ancestor comm names + env markers like
  `CLAUDECODE`). Uses: tighten rules, notification display ("**Claude Code** in
  `~/proj` wants …"), audit. Never relaxes. Sniff failure degrades to unattributable,
  never blocks.

### 4.3 Attribution ladder

1. **Declared human uids** (from `judo init`) → bypass judo entirely; stock sudo. This is
   also the lockout-safety story.
2. **Agent uids** → workspace policy (with any per-agent/per-harness overrides).
3. **Unattributable** (unknown user, exited PID, no signals) → workspace **baseline** —
   a missing label means no tightening applies, not a special tier.

### 4.4 Workspace attribution and cwd-shopping

Workspace = the `judo trust`'ed ancestor of the request's cwd. Because the agent controls
cwd, two guards: (a) a workspace `judo.toml` has **no effect until a human runs
`judo trust <dir>`** (direnv-style); (b) the hardline floor is global — no workspace
loosens it. Residual risk (out-of-tree damage from a trusted loose dir) is accepted in
v1; path-scoped loosening is a growth path (§14).

## 5. Danger policy

Full rationale: [Danger policy schema](https://github.com/leighstillard/judo/issues/8).

### 5.1 The ladder

Policy assigns one of four levels to a category:

| Level | Behaviour |
|---|---|
| `allow` | proceed silently (still audited) |
| `notify` | proceed immediately + fire-and-forget push |
| `approve` | block pending passkey ceremony |
| `deny` | refuse without asking |

The **hardline floor** — no-recovery-path operations (`rm -rf /`, `mkfs`, `dd` to raw
block devices, fork bombs, shutdown/reboot, …) — is **compiled into the binary** and is
not a policy level: not expressible, not referenceable, not loosenable by any config.

### 5.2 Categories

Built-in taxonomy with **stable IDs** (`fs.recursive-delete`, `db.drop`, `pkg.install`,
`net.pipe-to-shell`, `sudo.exec`, `svc.restart`, `policy.write`, …), seeded from the
Hermes ~72-pattern corpus re-sorted onto the ladder
([Hermes research](research/hermes-approval-subsystem.md)). Each built-in carries a
shipped default level. `judo.toml` may declare custom categories with their own match
rules, referenced by ID exactly like built-ins.

### 5.3 Classification

Rules match against the **normalized** command: NFKC, ANSI/null-strip, backslash-escape
folding (`r\m` → `rm`), empty-string-literal folding (`r''m` → `rm`), absolute-home
folding to `~/`, and command-position anchoring (start / after `;` `&&` `|` backtick
`$(`, skipping `sudo`/`env`/`nohup` wrappers). Ported wholesale from Hermes.

**Strictest wins**: every matching category is collected; effective level = most
restrictive (deny > approve > notify > allow). One approval envelope lists all matched
categories; a TTL grant on one category never covers a command that also matches a
stricter one. Order-independent — no rule-ordering footguns.

### 5.4 Layering

```text
shipped defaults → global ~/.config/judo/judo.toml → workspace judo.toml
                → [agents.<unix-user>] (loosen or tighten)
                → [harness.<label>]   (tighten only)
                → floors clamped      → strictest-wins across matches
```

The global file owns defaults, TTL ceilings, and per-category `floor = true` flags
(un-loosenable downstream). The workspace file owns category levels, `ttl_max` caps, and
the override tables.

### 5.5 Shape

```toml
# workspace judo.toml (at judo-trust'ed root)
default = "approve"          # unmatched commands (see 5.7)

[categories."fs.recursive-delete"]
level = "approve"            # allow|notify|approve|deny
ttl_max = "15m"              # enables + caps the TTL grant button (§6.1)

[categories."deploy.prod"]   # custom category
match = ['^\./deploy\.sh\s+prod']
level = "approve"

[agents.deploy-bot]          # Unix user: loosen or tighten
"pkg.install" = "allow"

[harness.claude-code]        # label: tighten only
"fs.recursive-delete" = "deny"

# global ~/.config/judo/judo.toml additionally supports:
[categories."policy.write"]
level = "approve"
floor = true                 # un-loosenable downstream
```

Workspace-configurable scalars also live here: `timeout` (default 90 s, §6.2),
`deny_cooldown` (default 10 m, §6.3).

### 5.6 Fail-safe and self-protection

- A layer that fails to parse is **dropped whole** (never partial application);
  resolution proceeds with remaining layers over shipped defaults, and the human gets a
  notify-channel alert naming the broken file. Not deny-all; not last-known-good.
- Built-in, floor-flagged **`policy.write`** covers every write path to `judo.toml` and
  the global config (editors, `tee`, `sed -i`, `cp`/`mv` — the full Hermes write-path
  corpus) at `approve`. The only way to relax policy is through a passkey ceremony.

### 5.7 Unmatched commands

Anything reaching judo has already hit a privilege point, so unmatched ⇒ the workspace's
`default` level, **shipped as `approve`** (fail-closed). Loosening it is an explicit,
auditable workspace choice, still clamped by floors. The classifier is an annotator,
never a blocklist whose gaps are bypasses.

## 6. Approval lifecycle

Full rationale: [Approval lifecycle semantics](https://github.com/leighstillard/judo/issues/6).

### 6.1 Grants

The approval page offers exactly two choices:

- **Approve once** — this precise envelope, one execution.
- **Approve `<category>` for N minutes** — scoped to (Unix user, workspace); offered only
  if the workspace `judo.toml` sets `ttl_max` for that category, N capped there. The
  phone can never grant more than policy allows.

**"Always" is not a button.** Permanent loosening happens only by editing `judo.toml` —
versioned, auditable, and itself gated by `policy.write`.

### 6.2 Timeout ≠ deny

Default 90 s (workspace-configurable). Agent-facing text is distinct:

- **DENY** → "denied by \<approver\> — do not retry; the human explicitly rejected this."
- **TIMEOUT** → "approval timed out — the human was unavailable; the request remains
  visible in `judo pending`; you may retry later."

A timed-out envelope outlives the blocked command: a late human tap pre-approves the
retry.

### 6.3 Duplicates

Coalescing key: **(command digest, Unix user, workspace)**. While an envelope for that
key is pending or late-approvable, retries attach to it — no second buzz. After an
explicit deny, identical commands **auto-deny silently for the cooldown** (default
10 min) — a retry loop doesn't re-litigate a human "no". Different command ⇒ fresh
envelope.

### 6.4 Unreachable approver

`judo pending` / `judo approve <id>` / `judo deny <id>` — valid **only from a declared-
human Unix login**; the kernel-verified login is the authenticator (no passkey at the
physical box). Notification failure still creates the envelope and logs loudly.
**No auto-approve path exists for agents under any failure.**

### 6.5 State machines

```text
envelope: pending → approved
                  → denied     (starts cooldown)
                  → timed-out  (late-approvable; page tap pre-approves retry)
                  → cancelled  (requester died; page shows it; NOT late-approvable)

grant:    active  → expired | revoked (judo revoke; effective next request,
                                       never yanks a running command)
```

Human dismissing the notification = timeout-equivalent (no cooldown). Every transition
is audited.

## 7. Approval protocol

Full rationale: [Design the end-to-end approval protocol](https://github.com/leighstillard/judo/issues/7).

### 7.1 Content-blind relay (E2E encryption)

The daemon encrypts each envelope body — argv, cwd, runas, uid, harness label +
confidence, workspace, human-readable summary, offered grant choices — with
**XChaCha20-Poly1305** under a random per-envelope key. Approval link:

```text
https://approve.judo.dev/a/<envelope-id>#<key>
```

The **fragment never reaches any server**; the page JS fetches ciphertext from the relay
and decrypts client-side (privatebin pattern). The relay stores only ciphertext +
routing metadata (envelope id, daemon id, expiry). AEAD integrity means only the daemon
can produce valid ciphertext — no separate envelope signature needed.

### 7.2 Challenge per grant-choice

A WebAuthn assertion signs only challenge + origin — the once-vs-TTL button choice would
otherwise travel unsigned, and a hostile relay could flip "once" into "TTL at cap".
Therefore the page requests ceremony options **after** the human taps a choice, and the
daemon mints the challenge bound to **(envelope, choice)** in a TTL'd map. Approving
once and approving a 15-minute grant are cryptographically different ceremonies.
Challenges are single-use.

### 7.3 Deny is unauthenticated

Link possession suffices to deny: deny can never escalate, and a malicious relay could
already "deny" by dropping envelopes. All state changes are **POST-only** so preview
fetchers and link scanners resolve nothing. Audit distinguishes link-authenticated page
denies from kernel-verified CLI denies.

### 7.4 Transport

- Daemon mints an **ed25519 keypair at `judo init`**; the public key registers it with
  the relay (key hash = daemon id; bearer token for reconnects).
- One persistent **outbound WebSocket** — no inbound ports, NAT-friendly, push both ways.
- Messages, daemon → relay: `create_envelope(id, ciphertext, expiry)`,
  `cancel_envelope(id)`, `verdict(id, approved|denied|timed_out|cancelled)` (page
  display). Relay → daemon: `page_event(id, opened | choice(c) | assertion(response) | deny)`.
- **Replay protection:** single-use webauthn-rs ceremony state (consumed on finish),
  single-use envelope ids (ULIDs), envelope expiry, idempotent-by-id replay of pending
  state on reconnect.

## 8. sudo interception

Full rationale: [sudo interception research](research/sudo-interception.md). The decisive
distinction is **auth-time** (PAM: sees identity, not the command; skipped by
NOPASSWD/cached timestamps) vs **authorization-time** (sudo 1.9 approval plugin: sees
argv + cwd + runas, true deny, fires even under NOPASSWD).

Layered design:

1. **Authorization = sudo 1.9 approval plugin.** One line in `/etc/sudo.conf`
   (`Plugin judo_approval judo_approval.so`, `.so` in `/usr/libexec/sudo/`). Its
   `check()` receives the full command context, sockets to the daemon, blocks on the
   verdict, and can truly deny. The skeleton prototypes this via sudo's Python plugin
   (`Plugin python_approval python_plugin.so ModulePath=… ClassName=…`) — ~40 lines,
   no FFI. `sudo.conf` and the plugin dir are `policy.write`-class protected paths.
2. **Authentication = judo PAM module** (Rust `pamsm` cdylib implementing
   `pam_sm_authenticate`) in the **"judo IS the credential"** model: the agent user has
   no password and no NOPASSWD, so `pam_authenticate` succeeds only when the module gets
   the daemon's say-so. No stored secret anywhere; askpass is UX transport only.

**Platform reality:** Ubuntu 25.10+ ships **sudo-rs, which has no plugin API** — PAM is
the only universal gate there, and it loses per-command visibility. The spec accepts
this degradation honestly: on sudo-rs, PAM gates *occurrence* (an approval is still
demanded), and per-command classification happens at judo's other interception points
until sudo-rs grows an approval-plugin story. macOS ships real sudo 1.9.13+ with full
plugin support.

## 9. WebAuthn / passkeys

Full rationale: [WebAuthn research](research/webauthn-passkeys.md).

### 9.1 Library and split

**`webauthn-rs`** (kanidm), Passkey flow, framework-free. The **daemon is the RP
verifier** (holds credential store, mints challenges, verifies assertions); the **relay
merely serves the page**. This split is legal WebAuthn — verification cares about
origin + rp_id hash in the signed client data, not who served the HTML.

### 9.2 RP identity

`rp_id = "judo.dev"` with `allow_subdomains(true)`; page origin `approve.judo.dev`.
The rp_id is **immutable forever** (changing it orphans every enrolled passkey) and
`judo.dev` stays **off the Public Suffix List**. Enrollment: QR at `judo init` / `judo
enroll` opens `https://judo.dev/enroll#<key>`; the daemon runs
`start/finish_passkey_registration` and stores the credential.

### 9.3 Bindings and caveats

- Challenge binding: daemon-side TTL'd **challenge → (envelope, choice)** map (§7.2);
  the library generates challenge bytes — they can't be injected.
- **Synced passkeys defeat counter-based clone detection** (signCount stays 0);
  don't build policy on signCount.
- **"What you see is what you sign":** the relay can't forge approvals but controls the
  page pixels. v1 mitigation: the notification itself echoes the exact command, so the
  human's trusted surface (their notification shade) shows the truth. Hardening path: a
  daemon-served approval page via tunnel (§14).

## 10. CLI surface

Accepted verbatim from the [CLI prototype](https://github.com/leighstillard/judo/issues/9)
(HITL-reviewed; the prototype file is absorbed here).

```text
judo — passkey privilege broker for AI agents

SETUP
  init                 One-time setup: identity, human declaration, relay pairing, first passkey
  enroll               Add a passkey (another phone/authenticator) to this daemon
  trust <dir>          Activate the judo.toml in <dir> as a trusted workspace
  untrust <dir>        Deactivate a trusted workspace

RUN
  daemon               Run the broker daemon (foreground; init system keeps it up)
  status               Daemon health: relay link, trusted workspaces, policy layers, active grants

POLICY
  classify <command>   Dry-run the classifier: matched categories + effective level, no approval fired
  policy               Show the resolved policy for the current directory (all layers merged)

APPROVALS (declared humans only — other users are refused)
  pending              List envelopes awaiting approval (incl. timed-out, late-approvable)
  approve <id>         Approve a pending envelope from this terminal (local fallback)
  deny <id>            Deny a pending envelope
  revoke [<grant-id>]  Revoke an active TTL grant (no id: list active grants)

AGENT SURFACE
  run <command>        Explicit brokered execution — fallback when transparent interception
                       isn't installed for a privilege point
```

Fixed behaviours:

- **`judo init` is one guided ceremony**: (1) mint ed25519 identity → (2) declare human
  Unix login(s) — judo's root of trust, editable later only via a `policy.write`-gated
  global-config edit → (3) relay pairing over the outbound WebSocket → (4) first passkey
  via QR (`https://judo.dev/enroll#<key>`; fragment key never reaches the relay).
- `judo trust` refuses a malformed `judo.toml` outright (parse error shown, nothing
  activated).
- `judo classify -- <cmd>` prints normalized form, each matched category with its level
  and source layer, the effective level, and the approver requirement; `--agent <user>`
  tests overrides. Read-only; never fires an approval.
- `judo status` surfaces dropped policy layers (§5.6) inline per workspace, plus active
  grants with remaining TTL.
- `judo approve` shows the exact command and confirms; recorded as `local-cli` approval,
  distinct from passkey approvals in audit.
- **No `--force`/`--yes` anywhere.** There is deliberately no CLI override of a deny.
- Deliberately absent from v1: audit viewer (tail the JSONL), channel management,
  passkey lifecycle beyond `enroll` — see §14.

## 11. Channel transport interface

Channels are **pure notification transports**; every approval is the same WebAuthn
ceremony regardless of channel. The interface is minimal:

```rust
trait Channel {
    /// Deliver a notification. `link` is the full approval URL (with fragment key).
    /// `text` MUST contain the exact-command echo (§9.3) — channels never truncate it.
    fn notify(&self, text: &str, link: &str) -> Result<(), ChannelError>;
}
```

Delivery failure is logged loudly and never blocks envelope creation (§6.4). v1 ships
one implementation: **ntfy** (topic configured in the global judo.toml). Slack, WhatsApp,
Telegram, and a native paid app are growth paths (§14).

## 12. Audit log

Graduated from map fog into this spec
([note](https://github.com/leighstillard/judo/issues/7)). Daemon-local, append-only
record of every envelope and state transition: creation (with full classified context),
notification dispatch, page opens, choice taps, ceremony results (passkey vs local-cli
vs link-deny), grant issue/expiry/revocation, policy-layer drops, and declared-human
bypasses are *not* logged (they never enter judo).

**Decision (annotated on the ticket, settled here): plain JSONL**, one event per line,
at `~/.local/state/judo/audit.jsonl`. Rationale: the only realistic tamperer is an
attacker with daemon-host root, and a hash chain doesn't survive that adversary — they
can rewrite the whole chain; genuine tamper-evidence needs an external anchor, which is
relay-productization territory (§14). JSONL is `tail`/`grep`/`jq`-able on day one and
costs nothing. Upgrade path if external anchoring arrives: add a `prev` hash field per
line and periodically checkpoint the head hash to the relay — additive, no format break.

## 13. Walking skeleton (scope for [#11](https://github.com/leighstillard/judo/issues/11))

Proves the full loop on one Ubuntu 24.04 box (sudo 1.9.15):
**agent runs `sudo` → approval plugin → daemon → ntfy push → phone opens link → passkey
ceremony → sudo proceeds.**

In: Python sudo approval plugin (sudo's `python_plugin.so`); Rust daemon with policy
engine (built-ins + one workspace judo.toml), envelope lifecycle, webauthn-rs
verification, JSONL audit; minimal relay (ciphertext store + static page + WebSocket);
ntfy channel; CLI: `init`, `trust`, `daemon`, `status`, `pending`, `approve`, `deny`,
`classify`.

Out (spec'd but post-skeleton): Rust PAM module, Rust sudo plugin, `enroll` beyond the
init passkey, `revoke`/TTL grants UI polish, multi-workspace ergonomics.

Skeleton exit test: with the phone on a different network, `sudo whoami` as the agent
user blocks, buzzes the phone showing the exact command, approves via passkey in under
15 s, and the command completes; `judo deny` from the human login kills a second attempt
with the deny message; a third identical attempt inside the cooldown auto-denies
silently.

## 14. Growth paths (from the map's fog — in scope for judo, out of scope for this spec's v1)

- **AWS credential brokering** — STS short-lived token vending per approval, via
  `credential_process`; design after the skeleton proves the broker model.
- **Database brokering** — per-approval connection vending or proxying.
- **Additional channels** — Slack/WhatsApp/Telegram/native app behind the §11 trait.
- **Relay productization** — multi-tenancy, hosting, pricing; plus external audit
  anchoring (§12) and daemon-served approval pages (§9.3).
- **Team flows** — multiple approvers, quorum, delegation.
- **Passkey lifecycle UX** — recovery, lost phone, authenticator management.
- **Harness integrations** — Claude Code hooks / MCP shim as a cooperative fast-path
  layered on (never replacing) the real broker.
- **Path-scoped loosening** — loose levels apply only when argv targets stay inside the
  workspace (closes the residual cwd-shopping risk, §4.4).
- **sudo-rs approval story** — upstream engagement or alternative gate when Ubuntu's
  default flips.

## References

- Map: [judo wayfinder map](https://github.com/leighstillard/judo/issues/1)
- Research: [Hermes approval subsystem](research/hermes-approval-subsystem.md) ·
  [sudo interception](research/sudo-interception.md) ·
  [WebAuthn/passkeys](research/webauthn-passkeys.md)
- Decisions: [agent identity](https://github.com/leighstillard/judo/issues/5) ·
  [approval lifecycle](https://github.com/leighstillard/judo/issues/6) ·
  [approval protocol](https://github.com/leighstillard/judo/issues/7) ·
  [danger policy schema](https://github.com/leighstillard/judo/issues/8) ·
  [CLI surface](https://github.com/leighstillard/judo/issues/9)
