#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JUDO="${ROOT}/target/debug/judo"
RELAY="${ROOT}/target/debug/judo-relay"

if [[ ! -x "${JUDO}" || ! -x "${RELAY}" ]]; then
  cargo build --workspace >/dev/null
fi

TMP="$(mktemp -d)"
cleanup() {
  [[ -n "${DAEMON_PID:-}" ]] && kill "${DAEMON_PID}" 2>/dev/null || true
  [[ -n "${RELAY_PID:-}" ]] && kill "${RELAY_PID}" 2>/dev/null || true
  rm -rf "${TMP}"
}
trap cleanup EXIT

export XDG_CONFIG_HOME="${TMP}/config"
export XDG_STATE_HOME="${TMP}/state"
mkdir -p "${XDG_CONFIG_HOME}/judo" "${XDG_STATE_HOME}/judo"

python3 - "${XDG_CONFIG_HOME}/judo/identity.json" "${ROOT}" <<'PY'
import base64, getpass, json, sys

path, root = sys.argv[1], sys.argv[2]
identity = {
    "daemon_id": "smoke-daemon",
    "ed25519_secret_b64": base64.b64encode(b"\x01" * 32).decode(),
    "ed25519_public_b64": base64.b64encode(b"\x02" * 32).decode(),
    "relay_url": "ws://127.0.0.1:18787/daemon",
    "humans": [getpass.getuser()],
    "ntfy_topic": "log",
    "passkeys": [],
    "trusted": [root],
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(identity, f)
PY

"${RELAY}" --listen 127.0.0.1:18787 >"${TMP}/relay.log" 2>&1 &
RELAY_PID=$!

for _ in $(seq 1 100); do
  if curl -fsS http://127.0.0.1:18787/api/debug/envelopes >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

"${JUDO}" daemon >"${TMP}/daemon.log" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 100); do
  if [[ -S "${XDG_STATE_HOME}/judo/judo.sock" ]] && "${JUDO}" status 2>/dev/null | grep -q "connected"; then
    break
  fi
  sleep 0.1
done

python3 - "${XDG_STATE_HOME}/judo/judo.sock" "${TMP}/request-response.json" "${ROOT}" <<'PY' &
import json, socket, sys

sock_path, out, root = sys.argv[1], sys.argv[2], sys.argv[3]
sock = socket.socket(socket.AF_UNIX)
sock.connect(sock_path)
sock.sendall((json.dumps({
    "t": "request",
    "uid": 99999,
    "cwd": root,
    "runas": "root",
    "argv": ["sudo", "whoami"],
}) + "\n").encode())
line = sock.makefile("r", encoding="utf-8").readline()
with open(out, "w", encoding="utf-8") as f:
    f.write(line)
PY
REQ_PID=$!

ENVELOPE_ID=""
for _ in $(seq 1 100); do
  PENDING="$("${JUDO}" pending 2>/dev/null || true)"
  ENVELOPE_ID="$(printf '%s\n' "${PENDING}" | awk 'NF { print $1; exit }')"
  if [[ -n "${ENVELOPE_ID}" ]]; then
    break
  fi
  sleep 0.1
done

if [[ -z "${ENVELOPE_ID}" ]]; then
  echo "no pending envelope appeared" >&2
  echo "--- daemon log ---" >&2
  cat "${TMP}/daemon.log" >&2
  echo "--- relay log ---" >&2
  cat "${TMP}/relay.log" >&2
  exit 1
fi

curl -fsS -X POST "http://127.0.0.1:18787/api/a/${ENVELOPE_ID}/deny" >/dev/null
wait "${REQ_PID}"

python3 - "${TMP}/request-response.json" "${ENVELOPE_ID}" <<'PY'
import json, sys

path, envelope_id = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    resp = json.loads(f.read())
assert resp["t"] == "verdict", resp
assert resp["verdict"] == "deny", resp
assert "denied by link" in resp["message"], resp
print(f"headless deny smoke passed: {envelope_id} -> {resp['verdict']} ({resp['message']})")
PY
