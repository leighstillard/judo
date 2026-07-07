# PROTOTYPE — judo CLI surface

> **Throwaway artifact.** This is a paper prototype answering one question for
> [#9 Prototype: judo CLI surface](https://github.com/leighstillard/judo/issues/9):
> *does this human-facing command surface feel right?* Nothing here is implemented.
> When the ticket closes, the verdict moves into the spec and this file is deleted or absorbed.
>
> **Verdict (2026-07-07):** accepted as prototyped — tree, init ceremony, top-level
> `classify`/`policy`, and the deliberate absences all confirmed. This surface feeds the
> spec ticket verbatim.

Every command below traces to a decided ticket. Provisional choices made just to be
concrete (things to react to) are marked **⚡** (all confirmed at review).

---

## The tree

```text
$ judo --help
judo — passkey privilege broker for AI agents

USAGE
  judo <command> [args]

SETUP
  init                 One-time setup: identity, human declaration, relay pairing, first passkey
  enroll               Add a passkey (another phone/authenticator) to this daemon
  trust <dir>          Activate the judo.toml in <dir> as a trusted workspace
  untrust <dir>        Deactivate a trusted workspace

RUN
  daemon               Run the broker daemon (foreground; use your init system to keep it up)
  status               Daemon health: relay link, trusted workspaces, policy layers, active grants

POLICY
  classify <command>   Dry-run the classifier: matched categories + effective level, no approval fired
  policy               Show the resolved policy for the current directory (all layers merged)

APPROVALS (declared humans only — other users are refused)
  pending              List envelopes awaiting approval
  approve <id>         Approve a pending envelope from this terminal (local fallback for phone-out days)
  deny <id>            Deny a pending envelope
  revoke [<grant-id>]  Revoke an active TTL grant (no id: list active grants)

AGENT SURFACE
  run <command>        Explicit brokered execution — fallback when transparent interception
                       (sudo plugin / PAM) isn't installed for a privilege point
```

---

## Walkthrough: day one

### 1. `judo init` — one ceremony, four facts

```text
$ judo init
judo init — one-time setup

[1/4] Identity
  ✓ Generated daemon keypair (ed25519) → ~/.config/judo/identity
    Public key: jd1qxk3...v8e2

[2/4] Humans
  Which Unix login(s) are YOU — a human whose commands bypass judo?
  (Agents must NOT be listed here. This is judo's root of trust.)
  > leigh
  ✓ Declared humans: leigh

[3/4] Relay pairing
  ✓ Connected to relay.judo.dev (outbound WebSocket)
  ✓ Daemon registered under its public key

[4/4] First passkey
  Scan this QR on the phone that will approve requests:

    █▀▀▀▀▀█ ▀▀█▄█ █▀▀▀▀▀█        https://judo.dev/enroll#Gk7...q2K
    █ ███ █ ▄▀ ▀▄ █ ███ █        (key after # never reaches the relay)
    ▀▀▀▀▀▀▀ ▀ ▀ ▀ ▀▀▀▀▀▀▀

  ... waiting ... ✓ Passkey enrolled: "Pixel 9 Pro" (leigh)

Done. Next steps:
  judo trust <dir>     activate a workspace
  judo daemon          start the broker
```

**⚡ Provisional:** humans declared interactively at init (editable later only via a
`policy.write`-gated edit of the global config). Enrollment is a QR on the daemon's
terminal — the phone never types a code.

### 2. `judo trust` — activate a workspace

```text
$ cd ~/work/api-server
$ judo trust .
Reading ./judo.toml ... ok (3 categories configured, 1 agent override)
Trusted: /home/leigh/work/api-server
  This workspace's judo.toml now applies to commands run under it.
  (Loosening below the global floor is ignored — floors always win.)
```

Refuses if `judo.toml` is malformed (parse error shown, nothing activated).

### 3. The agent hits sudo — nothing to type

```text
agent$ sudo systemctl restart api
[judo] approval required: sudo.exec, svc.restart → sent to your phone (envelope 01JXK...)
[judo] ... approved by leigh (Pixel 9 Pro) in 6s — proceeding
```

Phone shows: the **exact command**, cwd, agent (Unix user + harness label), matched
categories, and two buttons — *Approve once* / *Approve 15 min* (TTL cap from policy) —
each a separate passkey ceremony. Deny is one tap, no passkey.

### 4. `judo status` — what is judo enforcing right now?

```text
$ judo status
Daemon      running (pid 4211, up 3d 2h)
Relay       connected (relay.judo.dev, last envelope 6m ago)
Passkeys    2 enrolled (Pixel 9 Pro, YubiKey 5C)
Humans      leigh
Workspaces  2 trusted
  /home/leigh/work/api-server        ok
  /home/leigh/work/data-pipeline     ⚠ judo.toml PARSE ERROR line 14 — layer DROPPED,
                                       shipped defaults in effect (unmatched → approve)
Grants      1 active
  g_01JXM4  pkg.install  agent=deploy-bot  8m left  (revoke: judo revoke g_01JXM4)
```

The dropped-layer warning is the misconfiguration fail-safe made visible.

### 5. `judo classify` — test policy without buzzing anyone

```text
$ judo classify -- sudo rm -rf ./build
Command     sudo rm -rf ./build
Normalized  sudo rm -rf ./build
Matched     sudo.exec           approve   (workspace)
            fs.recursive-delete approve   (built-in default)
Effective   approve  (strictest of 2 matches)
Approver    passkey ceremony, TTL cap 15m (fs.recursive-delete)

$ judo classify --agent deploy-bot -- apt-get install jq
Matched     pkg.install  allow  (workspace [agents.deploy-bot] override)
Effective   allow
```

**⚡ Provisional:** `classify` is top-level (it's the command you'll teach people first),
`policy` shows the merged view; both read-only.

### 6. Phone unreachable — the local fallback

```text
$ judo pending
ID        AGE   AGENT       CATEGORIES            COMMAND
01JXN2Q   41s   claude-dev  db.drop               psql -c 'DROP TABLE staging_events'

$ judo approve 01JXN2Q
You are approving as declared human 'leigh' (kernel-verified login).
  psql -c 'DROP TABLE staging_events'
Approve once? [y/N] y
✓ approved (recorded as local-cli approval, distinct from passkey in audit)
```

Refused with an explanation if the caller isn't a declared human. Timed-out envelopes
appear in `pending` too (late-approvable, per the lifecycle decision).

### 7. `judo run` — the explicit fallback

```text
$ judo run -- aws s3 rb s3://prod-backups
[judo] aws.destructive → approval sent ... denied by leigh
[judo] refused: denied by approver (this is a human decision, not an error — do not retry)
```

Same pipeline as transparent interception; exists for privilege points that don't have
an interception shim yet.

---

## Deliberately absent

- `judo pair`/multi-device sync UI, recovery flows — passkey-lifecycle fog, not this map.
- Channel management beyond ntfy defaults — channels fog.
- `judo audit` viewer — audit log is a spec-ticket decision; the skeleton writes JSONL you can `tail`.
- Any `--force`/`--yes` flag anywhere. There is deliberately no CLI override of a deny.
