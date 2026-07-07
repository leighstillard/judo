# Session state — 2026-07-07

## Current task status

Wayfinder map for **judo** (passkey-gated privilege broker for AI agents) charted and first ticket resolved. Repo: https://github.com/leighstillard/judo (public), map + tickets on GitHub Issues with native sub-issue and blocked-by wiring.

**Resolved so far:**
- #2 "Research: Hermes approval subsystem" ✓ — asset `docs/research/hermes-approval-subsystem.md`. Adopt hardline floor / normalization / once-session-always / timeout≠deny / fail-closed unattended / policy self-protection; its cooperative trust model argues FOR judo's real-broker stance.
- #3 "Research: sudo interception mechanisms" ✓ — asset `docs/research/sudo-interception.md`. Gate = sudo 1.9 approval plugin (sees command, true deny, fires under NOPASSWD); skeleton prototypes it via sudo's Python plugin; spec layers plugin + judo PAM module ("judo IS the credential"). CRITICAL: sudo-rs (Ubuntu 25.10+, no plugin API) makes PAM the only universal gate — central platform tension for the spec.
- #4 "Research: WebAuthn/passkeys in Rust" ✓ — asset `docs/research/webauthn-passkeys.md`. webauthn-rs Passkey flow, daemon-as-verifier/relay-as-page-host split is legal WebAuthn; rp_id judo.dev + allow_subdomains, immutable, off PSL; challenge→envelope TTL map (can't inject challenge bytes); KEY: "what you see is what you sign" — relay controls pixels, mitigate via command echo in notification (skeleton) / daemon-served page (hardening); synced passkeys → signCount=0.
- #5 "Agent identity" ✓ (grilling) — tighten-only principle (forgeable signals never loosen policy); agent = Unix user (kernel-grade) + harness label (tighten/display/audit); declared humans bypass judo; unattributable = workspace baseline; cwd-shopping blocked by explicit `judo trust <dir>` + global hardline floor. CLI ticket #9 annotated with `judo trust` + `judo init` human declaration.
- #6 "Approval lifecycle" ✓ (grilling) — approve-once or policy-capped category TTL ("always" only via judo.toml); 90 s timeout, deny ≠ timeout, timed-out envelopes late-approvable; retries coalesce, 10-min post-deny cooldown; local fallback = judo pending/approve/deny from declared-human login, agents fail closed; requester death = cancelled; judo revoke for TTL grants. State machine: pending → approved|denied|timed-out|cancelled. CLI ticket #9 annotated.
- #7 "Approval protocol" ✓ (grilling) — envelopes E2E-encrypted (XChaCha20, key in URL fragment; relay content-blind); challenge minted per grant-choice (relay can't upgrade once→TTL); deny unauthenticated (fail-safe, POST-only); outbound WebSocket, daemon = ed25519 keypair from judo init; replay = single-use state/ids + expiry. Audit-log fog folded into spec ticket #10 (JSONL vs hash-chain decision annotated there).
- #9 "CLI surface prototype" ✓ (prototype) — accepted as prototyped: init/enroll/trust/untrust · daemon/status · classify/policy (top-level) · pending/approve/deny/revoke (declared humans only) · judo run fallback; init = one guided 4-step ceremony (identity → humans → relay pairing → passkey QR); no --force/--yes anywhere. Asset: docs/prototypes/cli-surface.md (feeds spec CLI section verbatim, then absorbed/deleted).
- #8 "Danger policy schema" ✓ (grilling) — ladder = allow/notify/approve/deny + compiled-in hardline floor (not expressible in config); built-in stable-ID taxonomy (Hermes corpus seed) + custom categories; strictest-wins across matches on normalized command; layers global (~/.config/judo, floor=true flags) → workspace judo.toml → [agents.<unix-user>] loosen/tighten + [harness.<label>] tighten-only, floors clamped last; unmatched = tunable `default`, ships approve; malformed layer dropped whole → shipped defaults + alert; floor-flagged policy.write gates policy-file writes. CLI ticket #9 annotated with `judo classify` + `judo status` dropped-layer surfacing.

## Key decisions made (during charting grill)

- Destination: buildable spec **+ walking skeleton** (sudo + ntfy round-trip)
- **Real broker** — judo holds the privilege; not a cooperative wrapper
- **Passkey (WebAuthn) ceremony per approval**; channels are pure notification transports carrying a link
- **Hosted relay** for stable HTTPS/RP domain + push; credentials stay on local daemon
- Danger policy: per-workspace `judo.toml` + per-agent overrides, deterministic classifier
- **Transparent interception** (SUDO_ASKPASS/PAM etc.) as primary agent surface
- **Rust**, single static binary
- Tracker: GitHub Issues (user disabled their "GitHub issues frozen — use Linear" hook for this)

## The map

- Map: [judo#1](https://github.com/leighstillard/judo/issues/1)
- Frontier (open, unblocked): #10 "Write the judo design spec" (task — all blockers 3✓,7✓,8✓,9✓ closed; annotated with audit-log section JSONL vs hash-chained decision)
- Blocked: #11 skeleton (by 10)
- Closed: #2 Hermes ✓, #3 sudo interception ✓, #4 WebAuthn ✓, #5 agent identity ✓, #6 lifecycle ✓, #7 protocol ✓, #8 policy schema ✓, #9 CLI prototype ✓
- Conventions: `docs/agents/issue-tracker.md`

## Pending issues

None. Repo committed and pushed (branch `master`).

## What to pick up next

`/wayfinder 10` (write the design spec — all decisions made, all inputs closed; this map carries execution per its Notes). Then #11 walking skeleton, and the map is done.
