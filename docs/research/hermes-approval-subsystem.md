# Research: Hermes approval subsystem — what judo should steal

Resolves [judo#2](https://github.com/leighstillard/judo/issues/2). Source studied: `/data/workspace/hermes/hermes-agent` at its 2026-07-07 working-tree state — chiefly `tools/approval.py` (1,943 lines, the single source of truth), `tools/terminal_tool.py` (sudo handling), `agent/file_safety.py`, `tools/write_approval.py`, `tools/slash_confirm.py`, and the regression tests under `tests/tools/`.

## How Hermes' system works

### Three-tier detection

1. **Hardline blocklist** (`HARDLINE_PATTERNS`, ~12 patterns) — commands with *no recovery path*: `rm -rf /`, `mkfs`, `dd` to raw block devices, fork bombs, `kill -1`, shutdown/reboot. Blocked unconditionally — survives `--yolo`, `approvals.mode=off`, and cron approve-mode. The comments are explicit that this is "a floor below yolo": trusting the agent with your files is not trusting it to power the box off. The list is deliberately tiny; recoverable-but-costly operations stay in the approvable tier.
2. **Dangerous patterns** (`DANGEROUS_PATTERNS`, ~60 regexes) — each is `(regex, human-readable description)`, and the *description doubles as the approval key* ("recursive delete", "SQL DROP", …). Covers rm/chmod/chown/dd, SQL (`DROP`, `DELETE` without `WHERE`, `TRUNCATE`), `curl | sh`, shell/interpreter `-c`/`-e`/heredoc execution, git destructive ops, service lifecycle (systemctl, docker), self-termination (killing its own gateway), and — most instructively — *every write path* to sensitive files.
3. **Unconditional guards** — `sudo -S` with no configured password is always blocked as a password brute-force vector (the LLM piping guessed passwords and reading "Sorry, try again").

### Anti-obfuscation normalization (`_normalize_command_for_detection`)

Before any pattern runs, the command is: ANSI-stripped (full ECMA-48), null-byte-stripped, Unicode NFKC-normalized (fullwidth chars), backslash-escape-folded (`r\m` → `rm`), empty-string-literal-folded (`r''m` → `rm`), and absolute home paths rewritten to `~/` (resolved at detection time, symlink-aware) so one static pattern catches `~/.bashrc`, `$HOME/.bashrc`, and `/home/alice/.bashrc` alike. Patterns that could false-positive on prose (`echo reboot`) are anchored to *command position* via a shared `_CMDPOS` fragment (start-of-string, after `;`/`&&`/`|`/backtick/`$(`, skipping `sudo`/`env`/`nohup` wrappers).

### Approval scopes and state

Choices are **once / session / always / deny**. Approval attaches to the *pattern key* (category), not the exact command — approving "recursive delete" once for the session covers all recursive deletes that session. "Always" persists the key to `command_allowlist` in `config.yaml`. Session state is thread-safe and keyed by a session key carried in `contextvars` (not process env — the gateway runs concurrent agent turns in executor threads). Each blocked thread gets its own `threading.Event` in a per-session FIFO queue; `/approve` resolves the oldest, `/approve all` resolves everything.

### Modes and contexts

- `approvals.mode`: `manual` | `smart` | `off`. **Smart** sends flagged commands to an auxiliary LLM (APPROVE / DENY / ESCALATE, escalate → human) before bothering the user — credited to OpenAI Codex's Smart Approvals guardian.
- **Cron / unattended**: fails closed by default (`cron_mode: deny`) with an instructive block message telling the agent to find another approach; the docstrings note that letting cron fall into the interactive path would "submit a pending approval with no listener and block the job indefinitely."
- **Containers** (docker/modal/daytona/singularity) bypass the layer entirely — nothing they run can damage the host. Hardline applies only to host-damaging environments (local, ssh, container-host cron).
- **YOLO is frozen at module import**: reading the env var per-call would let any code running in-process set it mid-session — an explicit prompt-injection escalation path they closed.

### Timeout and waiting semantics

CLI prompt: 60 s default, timeout → deny. Gateway: 300 s, and **timeout is reported distinctly from deny** to the post-approval hook. While blocked, the wait loop polls in 1 s slices and fires ~10 s activity heartbeats so the gateway watchdog doesn't kill the agent while the human is deciding.

### Single combined approval

`check_all_command_guards` gathers findings from *all* checkers (dangerous patterns + tirith content-security) into **one** approval request. Rationale in the docstring: a `force=True` replay must not bypass a check the user was never shown. `force=True` (set after the user confirms) skips the dangerous-command check on re-execution but is internal-only, never exposed to the model API — and hardline still applies under force.

### The "unpaired door" principle

Hermes' own `config.yaml` *is* the security policy (mode, yolo, allowlist), and the config cache is mtime-keyed, so a write takes effect mid-session. They therefore gate every mutation path to it: `write_file`/patch deny in file tools, plus terminal patterns for `>`/`>>`, `tee`, `sed -i`, `perl -i`/`ruby -i`, `cp`/`mv`/`install`. Repeated comment refrain: an unmatched write path makes the deny "unpaired theater." Same treatment for `~/.ssh/*`, shell rc files, `.netrc`/`.pgpass`/`.npmrc`/`.pypirc`, `.env` files. `file_safety.py` adds path-based write denies (exact files + prefixes: `~/.aws`, `~/.gnupg`, `~/.kube`, `/etc/sudoers.d`, `/etc/systemd`, …).

### Sudo handling (the part judo replaces)

If `SUDO_PASSWORD` is set in the env, Hermes rewrites `sudo` → `sudo -S` and pipes the password. Otherwise it probes `sudo -n` for NOPASSWD, or interactively prompts the human for their password (45 s timeout, cached per session). Messaging-platform users are literally tipped: "add SUDO_PASSWORD to .env on the agent machine."

### Peripheral machinery worth knowing

- **Staged pending writes** (`write_approval.py`): approval-gated writes are staged to disk (`pending/{memory,skills}/<id>.json`), surviving restarts, reviewed out-of-band from CLI/gateway/dashboard — with review affordances sized to content (small memory entries shown inline; 100 KB skills shown as gist + diff escape hatch).
- **Button UX** (`slash_confirm.py`): platforms with button UIs render Approve Once / Always / Cancel; others get text-reply fallback (`/approve`, `/always`, `/cancel`); pending confirms expire (300 s default).
- **Plugin hooks**: `pre_approval_request` / `post_approval_response` fire around every approval, non-blocking, errors swallowed — observability must never break the safety path.
- **Legacy-key aliases**: pattern keys were once derived from the regex text; when they switched to description-as-key they had to build `_PATTERN_KEY_ALIASES` to keep old allowlist entries working.

## What judo should adopt

1. **The hardline floor.** Judo's danger ladder needs a top rung — `deny` — that no approval, passkey or otherwise, can override. Keep the list tiny and limited to no-recovery-path operations.
2. **The normalization pipeline.** NFKC, ANSI-strip, escape-folding, home-path folding, command-position anchoring. This is hard-won anti-bypass discipline; port it wholesale into judo's classifier. (Several patterns credit Claude Code 2.1.113's deny rules and Mercury Agent's blocklist — three independent codebases converging on the same corpus.)
3. **Category-scoped approvals with a scope ladder.** once / session / always maps cleanly onto judo's danger levels; approval attaching to a *category* rather than an exact command string is the right granularity and matches judo's classifier→category→policy design. Feed the lifecycle ticket: Hermes has no TTL-based grant ("sudo for 15 min") — the scope ladder is its substitute.
4. **Timeout ≠ deny**, heartbeats while waiting, and per-session FIFO queues for concurrent pending approvals. Directly relevant to judo's approval lifecycle ticket.
5. **Fail-closed unattended contexts.** Cron/CI must never silently wait or silently pass; deny with a message that tells the agent what to do instead.
6. **Policy self-protection.** `judo.toml` and the daemon's own config/keys are themselves privileged write targets. Judo's broker position makes this structurally easier (policy lives behind the daemon boundary, not in the agent's writable filesystem) but the principle stands: every mutation path to policy gets gated, or the gate is theater.
7. **One combined approval per command** — never let a retry-after-partial-consent bypass a check the human didn't see; the passkey assertion should cover the *full* set of findings.
8. **Freeze bypass state at startup.** No env-var read at decision time may enable a bypass; Hermes froze YOLO at import for exactly this reason.
9. **Pre/post approval hooks** that can observe but never block or break the safety path — judo's audit-log fog patch will want this seam.
10. **Stable category IDs from day one.** Hermes' description-strings-as-keys forced a legacy-alias shim. Judo's categories are policy vocabulary; give them stable identifiers immediately.
11. **Durable pending requests.** Staging pending approvals to disk so they survive daemon restarts (write_approval's design) fits judo's daemon architecture.

## What judo should adapt

- **The pattern corpus as classifier seed.** Hermes' ~72 regexes (hardline + dangerous) are an excellent starting taxonomy for judo's command→category rules — but judo maps categories to a *danger ladder* (auto-allow / notify / passkey / deny), not Hermes' binary dangerous/not. The corpus needs re-sorting into categories, not copying.
- **Environment scoping.** Hermes skips approval entirely inside containers. Judo's equivalent is per-workspace policy (a sandbox workspace can set everything to auto-allow), which is more principled than a hardcoded backend list — but the insight "danger is relative to what the environment can touch" should be stated in the spec.
- **Button-style channel UX** (approve/always/cancel + text fallback + expiry) — good interaction grammar for judo's notification messages, except the button links to the passkey page rather than being the approval itself.

## What judo should reject

- **The cooperative trust model — and the arms race it forces.** Everything above runs *inside the agent's process*, gating its own tool calls. An agent with raw shell access bypasses all of it, and because policy/config live in the same trust domain as the agent, Hermes must chase every conceivable write path (`sed -i`, `tee`, `cp`, `perl -i`, macOS `/private` symlinks, unicode obfuscation…) and still calls its own coverage "unpaired theater" when one is missed. This is the strongest possible argument for judo's real-broker stance: when the daemon *holds the credential*, the enforcement point is possession, not detection — detection only decides *which* requests need a human, not whether the gate can be jumped.
- **`SUDO_PASSWORD` in `.env`.** Hermes' sudo story — standing plaintext password in an env file, auto-piped to `sudo -S`, with session-cached interactive fallback — is precisely the anti-pattern judo exists to delete. The unconditional `sudo -S` guard is Hermes patching around a hazard judo removes structurally.
- **LLM smart-approval as a gate.** Charting already fixed judo on a deterministic classifier; an approval gate that can be argued with is a weaker gate. (A notify-level LLM *triage annotation* — "this looks like a false positive" attached to the notification — could return later as fog, but never as the decision-maker.)
- **Global YOLO bypass.** Judo's per-workspace policy levels express "I trust this sandbox" in policy, auditable and scoped, rather than as a process-wide kill switch.

## Pointers into the other frontier tickets

- **Agent identity ([judo#5](https://github.com/leighstillard/judo/issues/5))**: Hermes identifies *sessions*, not agents — a session key bound via contextvars, with env fallback. It never solves cross-process agent attribution; judo's transparent-interception identity problem is genuinely novel territory.
- **Approval lifecycle ([judo#6](https://github.com/leighstillard/judo/issues/6))**: steal timeout≠deny, FIFO queues, heartbeat-while-waiting, fail-closed unattended mode; decide what Hermes never did — TTL grants and renotify.
- **Protocol ([judo#7](https://github.com/leighstillard/judo/issues/7))**: the combined-single-approval rule (assertion covers all findings) and durable pending envelopes belong in the protocol design.
- **Policy schema ([judo#8](https://github.com/leighstillard/judo/issues/8))**: seed categories from the pattern corpus; stable category IDs; hardline floor as a policy level; policy self-protection.
