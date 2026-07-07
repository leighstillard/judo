# Session state — 2026-07-07

## Current task status

Wayfinder map for **judo** (passkey-gated privilege broker for AI agents) charted and first ticket resolved. Repo: https://github.com/leighstillard/judo (public), map + tickets on GitHub Issues with native sub-issue and blocked-by wiring.

**Resolved this session:** ticket #2 "Research: Hermes approval subsystem" — closed with resolution comment; asset at `docs/research/hermes-approval-subsystem.md`; map's Decisions-so-far updated. Key takeaways: adopt Hermes' hardline floor / normalization pipeline / once-session-always category approvals / timeout≠deny / fail-closed unattended / policy self-protection; seed judo categories from its ~72-pattern corpus; its cooperative trust model is the argument FOR judo's real-broker stance.

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
- Frontier (open, unblocked): #3 sudo interception research, #4 WebAuthn/relay research, #5 agent identity (grilling), #6 approval lifecycle (grilling)
- Blocked: #7 protocol (by 4,6) → #8 policy schema (by 2✓,5) → #9 CLI prototype (by 7,8) → #10 spec (by 3,7,8,9) → #11 skeleton (by 10)
- Closed: #2 Hermes research ✓
- Conventions: `docs/agents/issue-tracker.md`

## Pending issues

None. Repo committed and pushed (branch `master`).

## What to pick up next

`/wayfinder 1` — next frontier ticket in order is #3 (sudo interception research, AFK). #4 is also AFK and parallelizable; #5/#6 are HITL grillings when the user is present.
