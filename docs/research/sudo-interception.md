# Research: how judo becomes the real privilege point for sudo

Resolves [judo#3](https://github.com/leighstillard/judo/issues/3). Sources: the sudo project man pages (`sudo_plugin(5)`, `sudo.conf(5)`, `sudoers(5)`, `sudo(8)`, `sudo_plugin_python(8)`) via the Ubuntu 24.04 "noble" mirror and sudo.ws; the sudo-rs repository and Ubuntu Server docs; the Rust PAM crates (`pamsm`, `pam-bindings`/`pam-rs`); and Jono Wells' "Making sudo Work with AI Agents". Verified locally on this machine (Ubuntu 24.04.4, `sudo -V` → **1.9.15p5**, `/etc/pam.d/sudo` present with `@include common-auth`, no `/etc/sudo.conf` so defaults apply, plugin dir `/usr/libexec/sudo/` ships `sudoers.so` + `sudo_intercept.so`). Read-only investigation; no system changes made.

## The one distinction that decides everything: auth-time vs authorization-time

sudo has two separable phases and judo must hook the right one.

1. **Authentication** — "is this the human they claim to be?" Handled by the **policy plugin** (`sudoers`), which on Linux delegates the credential check to **PAM** (`common-auth` in the stack above). Crucially, **sudo does not pass the command to PAM.** PAM modules see the invoking user, service name (`sudo`), tty, and rhost/ruser items — never the argv. Confirmed in `sudoers(5)`: PAM "is used solely for user authentication," and sudo only sets PAM's `ruser`/`rhost` items ([sudoers(5)](https://manpages.ubuntu.com/manpages/noble/man5/sudoers.5.html)). So a PAM module or askpass helper **cannot gate on *what* is being run** — it fires (or doesn't) purely on identity, and it is skipped entirely by NOPASSWD and by a cached timestamp.

2. **Authorization / approval** — "is this specific command allowed to run?" This is where the full command is visible. The **approval plugin** API (new in sudo 1.9) runs *after* the policy plugin has accepted the command and receives the argv, environment, and command metadata ([sudo_plugin(5)](https://manpages.ubuntu.com/manpages/noble/man5/sudo_plugin.5.html)).

Judo's requirement — "the human approves *this command* via passkey, and can deny it" — is an **authorization** requirement. That immediately favors the approval plugin over askpass/PAM for the *gate*, and relegates askpass/PAM to the *authentication* and *UX transport* roles.

---

## Mechanism 1 — SUDO_ASKPASS / askpass helper

**What it is.** An executable named in `sudo.conf` (`Path askpass /path/to/helper`) or via `$SUDO_ASKPASS`, invoked when sudo needs a password but has no usable tty, or when `-A`/`--askpass` is forced. It reads a password from the user and writes it to **stdout**; sudo then feeds that string into the normal PAM auth check ([sudo.conf(5)](https://manpages.ubuntu.com/manpages/noble/man5/sudo.conf.5.html), [sudo(8)](https://manpages.ubuntu.com/manpages/noble/man8/sudo.8.html)).

**What it can gate.** Nothing, on its own. The helper's output is checked against the user's *real* password by PAM. It sees no command, no argv, no target user beyond env. It cannot deny — it can only supply (or withhold) a credential. **A judo askpass helper cannot "vend an approval" unless judo already knows/sets the user's password** (i.e. judo *is* the credential — see below). This is the single most important correction to the naïve "askpass = approval" idea.

**Bypass resistance.** Weak as a gate. sudo prefers the tty prompt when a tty exists; askpass is only reached with no tty or `-A`. A cached timestamp or a NOPASSWD rule skips authentication, so the helper is never called. An agent with a tty (many do) bypasses it by design.

**Install cost.** Trivial: one `Path askpass` line in `/etc/sudo.conf`, or just `$SUDO_ASKPASS`. No root plugin ABI.

**Failure mode / lockout.** If the helper hangs, that sudo invocation hangs; the human's own interactive sudo is unaffected because it uses the tty prompt, not askpass. Fail-open/closed is entirely "did the helper return a valid password."

**Rust fit.** Perfect — it is just an executable reading a line and printing it. Trivial static Rust binary.

**Verdict.** Not a gate. Useful only as a **UX transport**: judo's askpass helper is what makes a no-tty agent's sudo *pause and phone home* instead of erroring, and it's where judo can inject a one-time credential once the passkey approval lands. Keep it in the toolbox as plumbing, not as the enforcement point.

## Mechanism 2 — Custom PAM module

**What it is.** A shared object dropped into the auth stack (`/etc/pam.d/sudo`, e.g. before/after `pam_unix`). It runs at authentication time.

**What it can gate.** Identity only. It can `pam_authenticate`-fail to block a sudo attempt (so it *can* deny), and it can call out to the judo daemon during `pam_sm_authenticate` — a PAM module is ordinary code and may open a socket. But per the distinction above, **it cannot see the command.** It also cannot reliably tell "which agent" — it gets the Unix user, tty, PID via `getpid()`/audit, but not a clean agent identity. And it is **skipped by NOPASSWD and cached timestamps**, so an agent that has *any* passwordless path never hits it.

**Bypass resistance.** Medium-to-weak. Fine as the "you must go through judo to authenticate at all" checkpoint *if* the agent user has no password and no NOPASSWD (judo-is-the-credential model), but it can't express per-command policy.

**Install cost.** Edit `/etc/pam.d/sudo` (root) and drop a `.so`. Editing the PAM stack is genuinely dangerous — a broken module can lock out *all* sudo including the human's. Installer must edit atomically, keep a fallback line, and ideally test with a held-open root shell.

**Rust fit.** Viable. `pamsm` ([crates.io](https://crates.io/crates/pamsm)) and `pam-bindings`/`pam-rs` ([GitHub](https://github.com/anowell/pam-rs)) build a `cdylib` `.so` implementing `pam_sm_authenticate`, linking `libpam`. Not a pure static binary — it's a shared object — but Rust produces it cleanly.

**Verdict.** A credible **authentication** checkpoint but blind to the command. Only interesting as one half of a layered design, or in the judo-is-the-credential model.

## Mechanism 3 — sudo 1.9+ approval plugin (the real answer)

**What it is.** A plugin type added in sudo 1.9 whose `check()` runs **after** the policy plugin accepts the command, receiving the full command context. From [sudo_plugin(5)](https://manpages.ubuntu.com/manpages/noble/man5/sudo_plugin.5.html), the `approval_plugin` struct's `check()` gets:

- `char * const command_info[]` — name=value pairs including the resolved command, **cwd**, **runas_uid/gid**, etc.
- `char * const run_argv[]` — the full argv to be `execve`'d.
- `char * const run_envp[]` — the environment.
- `const char **errstr` — message back to the user.

`check()` **returns 1 to allow, 0 to deny** (with `-1`/`-2` for errors) — so it is a true allow/deny gate, not merely authentication. **Multiple approval plugins may be registered and all must succeed**, and they run *alongside* the default `sudoers` policy — you add judo without replacing sudoers ([sudo.ws, "using the new approval API"](https://www.sudo.ws/posts/2020/08/sudo-1.9-using-the-new-approval-api-from-python/)).

**The decisive property: approval runs even when auth was skipped.** The approval `check()` is gated on the *policy plugin's* success, not on whether a password was collected. NOPASSWD and a cached timestamp make the policy succeed *without* authenticating — and the approval plugin **still runs**. This is exactly inverted from askpass/PAM, and it is precisely what judo needs: the human gets asked about the *command* every time, regardless of credential caching. (This should be verified once more against sudo source `plugin_approval()` before it's load-bearing in the spec, but it follows directly from the documented ordering: policy `check_policy` → approval `check` → I/O.)

**What it can gate.** Full command + args + cwd + runas + env, and it can deny. It calls out to the judo daemon from `check()` (open a Unix socket, push the approval, block until passkey verdict or timeout). It can distinguish the invoking user and PID; clean *agent* identity is still the open problem (feeds [judo#5]).

**Bypass resistance.** Strong within a genuine sudo install: the agent cannot skip the approval plugin without editing `sudo.conf` (which is itself a privileged write judo should gate). Unlike Hermes' in-process detection, the gate lives in sudo's own address space, not the agent's.

**Install cost.** One `Plugin` line in `/etc/sudo.conf` (e.g. `Plugin judo_approval judo_approval.so`) plus the `.so` in `/usr/libexec/sudo/`. Additive and low-risk relative to editing the PAM/policy stack — if the approval plugin fails to load, sudo still authenticates normally (fail-open unless configured otherwise).

**Failure modes / lockout safety.** This is the mechanism's best story. `check()` can implement: **daemon-down → fail-closed for agent users, fail-open (return 1) for the human's own login user**, distinguished by uid/parent-process/env. The human is never locked out of interactive sudo because judo's `check()` can whitelist them unconditionally. Timeout-while-waiting maps onto Hermes' "timeout ≠ deny" (see [judo#6]).

**Rust fit.** The plugin is a C-ABI `.so` loaded via `dlopen`, described by `<sudo_plugin.h>`. Rust produces this as a `cdylib` exposing the `approval_plugin` symbol — the same FFI shape as the PAM crates. No official Rust binding for the sudo plugin ABI exists today, so judo would hand-write the `#[repr(C)]` struct and the `sudo_conv`/`printf` callback glue (bindgen over `sudo_plugin.h`). Judo's "single static binary" ideal bends here: the plugin is a companion shared object, though it can be a thin shim that just forwards to the daemon over a socket, keeping all logic in the static daemon.

**Prototype fast in Python.** sudo ships `sudo_plugin_python(8)` (since 1.9.0): an approval plugin can be a Python class registered as `Plugin python_approval python_plugin.so ModulePath=… ClassName=…` ([sudo_plugin_python](https://www.sudo.ws/docs/man/1.9.0/sudo_plugin_python.man/)). Up to 8 Python approval plugins load at once. This lets the **walking skeleton** demo the end-to-end path (sudo → daemon → phone → passkey) in ~40 lines of Python before committing to the Rust cdylib.

## Mechanism 4 — NOPASSWD + wrapper/shim

**What it is.** Grant the agent (or a judo-owned binary) NOPASSWD in sudoers and interpose elsewhere: a setuid judo broker, or shadowing `sudo` earlier on `$PATH`.

**What it can gate.** A PATH shim sees the full command and can deny — but it is trivially bypassed (`/usr/bin/sudo` absolute path, or the agent editing its own PATH), so it fails judo's "structurally unable to bypass" bar. A setuid broker is really "judo replaces sudo," a much bigger surface. NOPASSWD alone is the *opposite* of a gate — it removes authentication and, notably, **does not remove the approval plugin** (mechanism 3 still fires), which is why NOPASSWD-for-agent + approval-plugin is a coherent pairing.

**Verdict.** Reject PATH-shimming and setuid brokers as the primary gate (bypassable / large surface). Keep NOPASSWD only as a *deliberate* companion to the approval plugin: it removes the pointless password step for a passwordless agent user while the approval plugin does the real gating.

---

## The reality check that reshapes the recommendation: sudo-rs

**Ubuntu 25.10 ships sudo-rs as the default `sudo`**, and it will flow into 26.04 LTS ([Ubuntu Server docs](https://ubuntu.com/server/docs/reference/other-tools/sudo-rs/), [sudo-rs repo](https://github.com/trifectatechfoundation/sudo-rs)). sudo-rs (v0.2.8 in 25.10) **does not implement the C plugin API at all** — no policy, approval, I/O, or audit plugins, no `sudoers.so` loading. So **mechanism 3 silently disappears on the platform judo most wants to support going forward.** A plugin-only judo would work on 24.04 (real sudo 1.9.15) and macOS, and break on 25.10+.

But sudo-rs **always uses PAM** ("your system must be set up for PAM… uses the `sudo` and `sudo-i` service configuration"). So the **PAM module (mechanism 2) is the one gate that survives the sudo → sudo-rs transition.** askpass in sudo-rs is not yet shipped — it was requested in [issue #1249](https://github.com/trifectatechfoundation/sudo-rs/issues/1249) (milestone "askpass", PR in flight) but is absent from the 0.2.8 README feature set. Treat askpass-on-sudo-rs as "coming, not here."

**macOS** ships real sudo (1.9.13 on Sequoia 15.6) with full `sudo.conf`/plugin support, so the approval plugin works there indefinitely — macOS is *more* plugin-friendly than future Ubuntu.

## The "judo IS the credential" angle

With the broker model you can make sudo *structurally* unable to succeed without judo: give the agent user **no password and no NOPASSWD**, so the only way `pam_authenticate` can pass is through a judo-controlled PAM module (mechanism 2) that returns success only after a passkey approval. This is clean on both sudo and sudo-rs (both go through PAM). The catch, restated plainly: **askpass alone can't do this** — askpass output is verified against the real password by PAM, so an askpass helper can only unlock sudo if judo *knows or sets* that password (e.g. judo owns a random password it injects via askpass after approval). A PAM module that talks to the daemon is the cleaner "judo is the credential" implementation because it needs no stored secret — it just returns `PAM_SUCCESS` on the daemon's say-so. Its limitation stands: it gates *identity/occurrence*, not the *command*.

---

## Recommendation

**Walking skeleton ([judo#11]): sudo 1.9 approval plugin, prototyped in Python.** Fastest credible full loop — the approval plugin's `check()` already hands you argv + cwd + runas, can deny, and can socket to the daemon. On this Ubuntu 24.04 / sudo 1.9.15 box it's a `sudo.conf` `Plugin python_approval …` line plus a small Python class that POSTs to the judo daemon and blocks on the verdict. Demonstrates agent-runs-sudo → daemon → phone → passkey → command proceeds with no password stored anywhere and true deny. ~40 lines, no Rust FFI yet.

**Spec ([judo#10]): a layered design, not one mechanism.**

- **Primary gate = approval plugin (Rust `cdylib` shim → daemon).** It is the only mechanism that sees the full command *and* can deny *and* still fires under NOPASSWD/cached-timestamp. Keep plugin logic thin; all policy in the static daemon.
- **Authentication = judo PAM module (Rust `pamsm` cdylib) in the "judo is the credential" model** — agent user has no password/NOPASSWD; PAM success comes only from the daemon. This is what carries judo onto **sudo-rs** (25.10+), where the plugin gate is unavailable. On sudo-rs, the PAM module is the *whole* gate and loses per-command visibility — the spec must state this degradation honestly and lean on per-command policy at the daemon's other interception points until sudo-rs grows a plugin/approval story.
- **askpass helper = UX transport only** — makes no-tty agents pause-and-phone-home and injects the one-time credential post-approval; never trusted as the gate.
- **NOPASSWD = deliberate companion** to the approval plugin for passwordless agent users; never used to *skip* judo.
- **Lockout safety:** approval `check()` and the PAM module both whitelist the human's own login uid unconditionally / fail-open for them, fail-closed for agent users when the daemon is unreachable. Never edit the PAM/policy stack without an atomic install and a held-open fallback shell.
- **Version matrix to encode in the spec:** Ubuntu 22.04/24.04 + Debian 12 + macOS → approval plugin (sudo ≥1.9.9 everywhere; 1.9.13–1.9.15 observed). Ubuntu 25.10+/26.04 (sudo-rs) → PAM module only until sudo-rs ships plugins/askpass. This split is the central design tension and belongs up front.

## Surprises / notes for adjacent tickets

- **[judo#7] protocol:** the daemon's request envelope must carry argv + cwd + runas + invoking uid/pid (everything `command_info[]`/`run_argv[]` expose) so a passkey assertion binds to the exact command — mirrors Hermes' "one combined approval covers all findings."
- **[judo#5] agent identity:** neither the plugin nor PAM gives clean agent attribution — both see Unix user + PID + tty only. Still novel territory, as the Hermes research flagged.
- **[judo#6] lifecycle:** timeout-while-`check()`-blocks is where "timeout ≠ deny," heartbeats, and fail-closed-unattended land.
