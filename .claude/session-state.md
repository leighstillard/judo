# Session state — 2026-07-07

## Current task status

Wayfinder map for **judo** (passkey-gated privilege broker for AI agents) fully charted. Repo created at https://github.com/leighstillard/judo (public), map + 10 tickets live on GitHub Issues with native sub-issue and blocked-by wiring. Charting session complete; no tickets resolved yet (per wayfinder rule).

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
- Frontier (open, unblocked): #2 Hermes research, #3 sudo interception research, #4 WebAuthn/relay research, #5 agent identity (grilling), #6 approval lifecycle (grilling)
- Blocked: #7 protocol (by 4,6) → #8 policy schema (by 2,5) → #9 CLI prototype (by 7,8) → #10 spec (by 3,7,8,9) → #11 skeleton (by 10)
- Conventions: `docs/agents/issue-tracker.md`

## Pending issues

None. Repo committed and pushed (branch `master`).

## What to pick up next

`/wayfinder https://github.com/leighstillard/judo/issues/1` — it will claim the first frontier ticket (#2 Hermes research, AFK) or run #5/#6 as HITL grillings. Research tickets #2–#4 are AFK and parallelizable.

Hermes source for ticket #2: `/data/workspace/hermes/hermes-agent` (tools/approval.py, agent/file_safety.py, tools/slash_confirm.py).
