# Walking skeleton — live exit test (spec §13)

The headless deny path is already verified. This is the **HITL half**: prove the full
loop with a real phone and a real passkey.

**Loop under test:** agent runs `sudo` → judo approval plugin → daemon → ntfy push to
your phone → you approve with a passkey on the approval page → `sudo` proceeds.

You run this on your dev box with your phone. `judo.stillard.com` is the WebAuthn RP
(passkeys bind to it, so enrolments persist across restarts).

---

## 0. One-time prerequisites

- **A second Unix user to act as the "agent"** (your own login is a *declared human* and
  bypasses judo). Create a throwaway:
  ```bash
  sudo useradd -m -s /bin/bash agentbot
  ```
- **A phone** with a platform authenticator (Face ID / fingerprint / screen lock).
- **A tunnel** so `https://judo.stillard.com` reaches the local relay with valid TLS
  (WebAuthn refuses non-secure / mismatched origins). Two ways:

  **A. Cloudflare named tunnel (recommended — stable host, if stillard.com is on Cloudflare):**
  ```bash
  cloudflared tunnel login
  cloudflared tunnel create judo
  cloudflared tunnel route dns judo judo.stillard.com
  # run it, forwarding to the local relay (step 2):
  cloudflared tunnel --url http://127.0.0.1:8787 run judo
  ```
  **B. Quick tunnel (zero DNS, ephemeral host — fallback):**
  ```bash
  cloudflared tunnel --url http://127.0.0.1:8787
  # note the printed https://<random>.trycloudflare.com host and use THAT as RP id below
  ```

**No env vars needed.** The relay WebSocket URL you enter at `judo init` (step 3) is the
single source of truth: its host becomes the WebAuthn `rp_id`, the approval-page origin,
and the enroll-QR target. Point the tunnel at `judo.stillard.com` and enter
`wss://judo.stillard.com/daemon` at init — everything follows from that.

---

## 1. Build

```bash
cd /data/workspace/judo
cargo build --workspace
```

## 2. Start the relay (terminal 1)

```bash
./target/debug/judo-relay --listen 127.0.0.1:8787
```
Point your tunnel (step 0) at `http://127.0.0.1:8787`. Confirm
`https://judo.stillard.com/enroll` loads on your phone before continuing. The relay MUST
be listening before the tunnel can reach it (a `connection refused` in the cloudflared
log means it isn't up yet).

## 3. Initialise (terminal 2)

```bash
./target/debug/judo init
```
- Declared human login: **your** username (NOT `agentbot`).
- Relay URL: **`wss://judo.stillard.com/daemon`** — it MUST be `wss://` (not `ws://`): the
  tunnel is HTTPS, so the derived page origin must be `https://` or WebAuthn rejects the
  origin mismatch, and the daemon's own WebSocket needs `wss://` through the tunnel.
- ntfy topic: any unique string; subscribe to it in the ntfy app on your phone
  (or watch the daemon stdout — the skeleton also prints the push).

`init` prints the enroll QR and saves identity. **Do not scan/enrol yet** — enrolment
needs the daemon running (next step).

## 4. Run the daemon, THEN enrol (terminal 2)

```bash
./target/debug/judo daemon
```
Confirm with `judo status` (terminal 3) that the relay shows **connected** — the enrol
button calls the relay, which forwards to the connected daemon to mint the passkey
challenge. With no daemon connected the button silently fails.

**Now** scan the QR (or reload `https://judo.stillard.com/enroll`) → tap **Enroll
passkey** → authenticate with Face ID / fingerprint. `judo status` should then show 1
passkey.

## 5. Make the agent user hit sudo, and gate it with the plugin

Install the approval plugin so `agentbot`'s sudo routes through judo. As root, add to
`/etc/sudo.conf`:
```
Plugin judo_approval /data/workspace/judo/target/release/libjudo_sudo_plugin.so
```
(Build it first: `cargo build -p judo-sudo-plugin --release`.) Give `agentbot` a sudo
entry that still requires the approval plugin (the plugin runs at authorization time,
after sudoers). For the skeleton, simplest is to let `agentbot` attempt a harmless
privileged command.

## 6. The exit test

From the **agent** user, with your phone on a **different network** (mobile data, to prove
it's not a same-LAN trick):

```bash
sudo -u agentbot -i
# as agentbot:
sudo whoami
```

**Expected — the pass criteria:**
1. `sudo whoami` **blocks**.
2. Your phone buzzes; the notification shows the **exact command** (`sudo whoami`), the cwd,
   and that **agentbot** (not you) is asking.
3. Open the link, tap **Approve once**, authenticate with the passkey.
4. Back in the terminal, `sudo whoami` completes and prints `root` — **in under ~15 s**.

**Then prove deny + cooldown:**
5. `sudo whoami` again → this time tap **Deny** on the phone (or run `judo deny <id>` from
   your human login). The command fails with *"denied by … — do not retry"*.
6. `sudo whoami` a **third** time within 10 minutes → it **auto-denies silently** (no second
   buzz) — the post-deny cooldown.

If all six hold, the skeleton is proven and ticket #11 is done.

---

## Notes / known skeleton edges (spec-tracked, not bugs)

- **ntfy** is stubbed to a stdout/log push in the skeleton; the phone notification arrives
  via the ntfy app subscription or you read the link from the daemon log. Real push is the
  §11 channel work.
- **Hand-rolled page crypto**: the approval page decrypts the envelope with an inlined
  XChaCha20-Poly1305 (verified correct against a live daemon envelope). Swap in
  `noble-ciphers` before any real deployment.
- **`rp_id` is derived from the relay URL host** — one input at `init` drives rp_id, the
  approval-page origin, and the enroll QR. Keep the relay host stable across sessions or
  enrolled passkeys orphan (they bind to rp_id).
- Relay `Hello` trusts the claimed daemon key (skeleton); production verifies an ed25519
  challenge (spec §7.4).
