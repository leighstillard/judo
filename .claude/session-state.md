# Session state — 2026-07-07

## Current task status

Wayfinder map for **judo** (passkey-gated privilege broker for AI agents) charted and first ticket resolved. Repo: https://github.com/leighstillard/judo (public), map + tickets on GitHub Issues with native sub-issue and blocked-by wiring.

**Resolved so far:**
- #2 "Research: Hermes approval subsystem" ✓ — asset `docs/research/hermes-approval-subsystem.md`. Adopt hardline floor / normalization / once-session-always / timeout≠deny / fail-closed unattended / policy self-protection; its cooperative trust model argues FOR judo's real-broker stance.
- #3 "Research: sudo interception mechanisms" ✓ — asset `docs/research/sudo-interception.md`. Gate = sudo 1.9 approval plugin (sees command, true deny, fires under NOPASSWD); skeleton prototypes it via sudo's Python plugin; spec layers plugin + judo PAM module ("judo IS the credential"). CRITICAL: sudo-rs (Ubuntu 25.10+, no plugin API) makes PAM the only universal gate — central platform tension for the spec.
- #4 "Research: WebAuthn/passkeys in Rust" ✓ — asset `docs/research/webauthn-passkeys.md`. webauthn-rs Passkey flow, daemon-as-verifier/relay-as-page-host split is legal WebAuthn; rp_id judo.dev + allow_subdomains, immutable, off PSL; challenge→envelope TTL map (can't inject challenge bytes); KEY: "what you see is what you sign" — relay controls pixels, mitigate via command echo in notification (skeleton) / daemon-served page (hardening); synced passkeys → signCount=0.

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
- Frontier (open, unblocked): #5 agent identity (grilling, HITL), #6 approval lifecycle (grilling, HITL)
- Blocked: #7 protocol (by 4✓,6) → #8 policy schema (by 2✓,5) → #9 CLI prototype (by 7,8) → #10 spec (by 3✓,7,8,9) → #11 skeleton (by 10)
- Closed: #2 Hermes ✓, #3 sudo interception ✓, #4 WebAuthn ✓
- Conventions: `docs/agents/issue-tracker.md`

## Pending issues

None. Repo committed and pushed (branch `master`).

## What to pick up next

`/wayfinder 1` — all remaining frontier tickets are HITL grillings: #5 (agent identity) then #6 (approval lifecycle). Both need the user present; #6 unblocks #7 (protocol), #5 unblocks #8 (policy schema).
