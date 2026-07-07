# judo

A passkey-gated privilege broker for AI agents.

Judo lets AI agents reach privileged or dangerous commands (`sudo`, AWS mutations, DB drops) only through a human approval: the agent hits the privilege point, judo intercepts, your phone buzzes with an approval link, and you approve with a passkey (WebAuthn). No approval, no privilege — judo *holds* the credentials, so there is nothing to bypass.

## Status

Design phase. The way to a buildable spec + walking skeleton is being charted as a [wayfinder map](docs/agents/issue-tracker.md) on this repo's GitHub Issues.

## Core design decisions (so far)

- **Real broker, not cooperative wrapper** — judo is the privilege point itself (sudo askpass/PAM, credential vending), so agents can't route around it.
- **Passkey ceremony per approval** — notification channels (ntfy, Slack, WhatsApp, …) only carry the link; every approval is a WebAuthn ceremony on judo's approval page.
- **Hosted relay** — a dumb, end-to-end-signed envelope relay provides the stable HTTPS domain and push. Credentials never leave the local daemon.
- **Per-workspace danger policy** — `judo.toml` maps command categories to danger levels, with per-agent overrides.
- **Rust**, single static binary. Walking skeleton: sudo + ntfy.
