"""Privasys container-app-example.

Demonstrates the configure-then-freeze pattern AND the two kinds of
stateful data that drive the enclave-upgrade approval flows:

  1. The app boots frozen. Every endpoint other than POST /configure
     returns 503 with ``{"error": "app is awaiting initial configuration"}``.
  2. The deployer POSTs ``{"api_key": "..."}`` to /configure. The app
     a. stores the key under /data/api_key (per-app sealed volume),
     b. computes SHA-256(api_key),
     c. POSTs the hash to the local manager
        ``http://127.0.0.1:9443/api/v1/containers/{name}/attestation-extensions``
        so the next per-container RA-TLS leaf advertises the commitment
        under OID ``1.3.6.1.4.1.65230.3.5.1``,
     d. POSTs ``.../config-complete`` to lift the freeze.
  3. /protected returns 200 once configured.
  4. On restart the in-memory ``configured`` flag resets to False.

# Stateful data (drives the upgrade-approval scenarios)

Everything below lives on /data, the per-app encrypted volume whose DEK
is reconstructed from the Enclave Vault constellation at boot. Two
namespaces, gated by two different key-holders on an upgrade:

  * ``/store/{key}``            — general APP data. Encrypted under the
    app's own storage key. When the enclave (mini/virtual) OR the app is
    upgraded, the APP OWNER approves the new measurement and the app
    storage key is released to it, so /store data carries forward.

  * ``/owner-data/{owner_id}/{key}`` — DATA-OWNER data, segregated per
    data owner. In the full model each data owner's slice is wrapped with
    that owner's vault key, so on an upgrade EACH data owner independently
    approves the new measurement before their slice is readable again;
    a data owner who declines keeps their data locked to the old version.
    (The app provides the data surface here; the per-owner key-wrapping is
    the Phase G data-owner-keys infrastructure.)

The launcher injects ``PRIVASYS_CONTAINER_NAME`` and
``PRIVASYS_CONTAINER_TOKEN``; the manager middleware enforces
(loopback + token + name) before honouring SDK callbacks.
"""

import base64
import hashlib
import http.client
import http.server
import json
import os
import re
import threading
from pathlib import Path
from urllib.parse import urlparse

# ── Per-app state ────────────────────────────────────────────────────
_CONFIG_LOCK = threading.Lock()
_CONFIGURED = False  # in-memory: re-armed on every container restart
_DATA_DIR = Path("/data")
_KEY_PATH = _DATA_DIR / "api_key"

# Stateful-data roots on the per-app sealed volume.
_STORE_DIR = _DATA_DIR / "store"            # general app data
_OWNERS_DIR = _DATA_DIR / "owners"          # data-owner-segregated data

# Keys/owner-ids are path components on the sealed volume — keep them to
# a safe charset so they can never escape their namespace.
_SAFE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

_MANAGER_HOST = "127.0.0.1"
_MANAGER_PORT = 9443

_NAME = os.environ.get("PRIVASYS_CONTAINER_NAME", "")
_TOKEN = os.environ.get("PRIVASYS_CONTAINER_TOKEN", "")


def _post_to_manager(path: str, body: dict) -> tuple[int, bytes]:
    """POST a JSON body to the local manager and return (status, body)."""
    if not _NAME or not _TOKEN:
        raise RuntimeError(
            "PRIVASYS_CONTAINER_NAME / PRIVASYS_CONTAINER_TOKEN missing; "
            "is this container running on enclave-os-virtual?"
        )
    conn = http.client.HTTPConnection(_MANAGER_HOST, _MANAGER_PORT, timeout=5)
    try:
        conn.request(
            "POST",
            path,
            body=json.dumps(body),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {_TOKEN}",
            },
        )
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _do_configure(api_key: str) -> None:
    """Persist + commit + unfreeze. Raises on any failure."""
    if not api_key:
        raise ValueError("api_key must be non-empty")

    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _KEY_PATH.write_text(api_key)
    os.chmod(_KEY_PATH, 0o600)

    digest = hashlib.sha256(api_key.encode("utf-8")).digest()
    status, body = _post_to_manager(
        f"/api/v1/containers/{_NAME}/attestation-extensions",
        {
            "oid": "1.3.6.1.4.1.65230.3.5.1",
            "value_b64": base64.standard_b64encode(digest).decode("ascii"),
        },
    )
    if status >= 300:
        raise RuntimeError(f"manager attestation-extensions: {status} {body!r}")

    status, body = _post_to_manager(
        f"/api/v1/containers/{_NAME}/config-complete",
        {},
    )
    if status >= 300:
        raise RuntimeError(f"manager config-complete: {status} {body!r}")


# ── Stateful-data helpers ────────────────────────────────────────────

def _safe(component: str) -> bool:
    return bool(_SAFE.match(component or ""))


def _store_path(key: str) -> Path:
    return _STORE_DIR / key


def _owner_path(owner_id: str, key: str) -> Path:
    return _OWNERS_DIR / owner_id / key


def _write_value(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    os.chmod(path, 0o600)


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _is_frozen_for(self, path: str) -> bool:
        # Health check is always available so the manager's readiness
        # probe can see the container is up even before configuration.
        if path == "/health":
            return False
        with _CONFIG_LOCK:
            return not _CONFIGURED

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length) if length else b""

    # ── GET ──────────────────────────────────────────────────────────
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if self._is_frozen_for(path):
            self._json(503, {"error": "app is awaiting initial configuration"})
            return

        if path == "/health":
            self._json(200, {"status": "healthy"})
        elif path == "/protected":
            try:
                key = _KEY_PATH.read_text()
            except FileNotFoundError:
                self._json(500, {"error": "api_key file missing"})
                return
            self._json(200, {"status": "ok", "api_key_length": len(key)})
        elif path == "/":
            self._json(200, {"status": "ok", "name": _NAME})
        elif path.startswith("/store/"):
            self._get_store(path[len("/store/"):])
        elif path == "/store":
            self._list_dir(_STORE_DIR)
        elif path.startswith("/owner-data/"):
            self._get_owner_data(path[len("/owner-data/"):])
        else:
            self._json(404, {"error": "not found"})

    def _get_store(self, key: str) -> None:
        if not _safe(key):
            self._json(400, {"error": "invalid key"})
            return
        try:
            value = _store_path(key).read_bytes()
        except FileNotFoundError:
            self._json(404, {"error": "key not found"})
            return
        self._json(200, {"key": key, "value": value.decode("utf-8", "replace")})

    def _get_owner_data(self, rest: str) -> None:
        parts = rest.split("/", 1)
        owner_id = parts[0]
        if not _safe(owner_id):
            self._json(400, {"error": "invalid owner_id"})
            return
        if len(parts) == 1 or parts[1] == "":
            # List a data owner's keys.
            self._list_dir(_OWNERS_DIR / owner_id, label="owner_id", label_value=owner_id)
            return
        key = parts[1]
        if not _safe(key):
            self._json(400, {"error": "invalid key"})
            return
        try:
            value = _owner_path(owner_id, key).read_bytes()
        except FileNotFoundError:
            self._json(404, {"error": "key not found"})
            return
        self._json(200, {"owner_id": owner_id, "key": key,
                         "value": value.decode("utf-8", "replace")})

    def _list_dir(self, d: Path, label: str | None = None,
                  label_value: str | None = None) -> None:
        try:
            keys = sorted(p.name for p in d.iterdir() if p.is_file())
        except FileNotFoundError:
            keys = []
        out: dict = {"keys": keys, "count": len(keys)}
        if label:
            out[label] = label_value
        self._json(200, out)

    # ── POST ─────────────────────────────────────────────────────────
    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path

        if path == "/configure":
            self._configure()
            return

        if self._is_frozen_for(path):
            self._json(503, {"error": "app is awaiting initial configuration"})
            return

        if path.startswith("/store/"):
            self._put_store(path[len("/store/"):])
        elif path.startswith("/owner-data/"):
            self._put_owner_data(path[len("/owner-data/"):])
        else:
            self._json(404, {"error": "not found"})

    def _value_from_body(self) -> tuple[bytes | None, str | None]:
        raw = self._read_body()
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return None, "invalid JSON body"
        value = payload.get("value")
        if not isinstance(value, str):
            return None, "value (string) is required"
        return value.encode("utf-8"), None

    def _put_store(self, key: str) -> None:
        if not _safe(key):
            self._json(400, {"error": "invalid key"})
            return
        value, err = self._value_from_body()
        if err:
            self._json(400, {"error": err})
            return
        _write_value(_store_path(key), value)
        self._json(200, {"status": "stored", "key": key, "bytes": len(value)})

    def _put_owner_data(self, rest: str) -> None:
        parts = rest.split("/", 1)
        if len(parts) != 2 or not parts[1]:
            self._json(400, {"error": "path must be /owner-data/{owner_id}/{key}"})
            return
        owner_id, key = parts
        if not _safe(owner_id) or not _safe(key):
            self._json(400, {"error": "invalid owner_id or key"})
            return
        value, err = self._value_from_body()
        if err:
            self._json(400, {"error": err})
            return
        _write_value(_owner_path(owner_id, key), value)
        self._json(200, {"status": "stored", "owner_id": owner_id,
                         "key": key, "bytes": len(value)})

    def _configure(self) -> None:
        try:
            payload = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON body"})
            return
        api_key = payload.get("api_key", "")
        if not isinstance(api_key, str) or not api_key:
            self._json(400, {"error": "api_key (string) is required"})
            return
        try:
            _do_configure(api_key)
        except Exception as exc:  # noqa: BLE001 — surface manager error
            self._json(500, {"error": str(exc)})
            return
        global _CONFIGURED
        with _CONFIG_LOCK:
            _CONFIGURED = True
        self._json(200, {"status": "configured"})

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", 8080), Handler)
    print(f"container-app-example listening on :8080 (name={_NAME or '<unset>'})")
    server.serve_forever()
