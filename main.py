"""Privasys container-app-example-with-config.

Reference app for the typed config + actions capabilities on the Privasys
container runtime. It demonstrates THREE things:

  1. CONFIGURE-THEN-FREEZE, gated at the routing layer (NOT in the app).
     The manifest declares a `config` block whose endpoint is POST /configure.
     The enclave manager keeps every other path at HTTP 503 until the first
     successful (2xx) response from /configure, then lifts the gate
     automatically. The gate re-arms on each restart. This app contains NO
     freeze flag and NO 503 gating of its own, and it does NOT call
     `config-complete`: the manager owns the gate.

  2. TYPED ACTIONS. The manifest declares an action `process` with a dynamic
     enum input (the dataset list is fetched live from GET /datasets) and a
     progress channel (GET /actions/process/status). The portal, CLI, and MCP
     render and drive it generically.

  3. STATEFUL DATA on /data (the per-app sealed volume) for the
     enclave-upgrade approval scenarios: general app data under /store and
     data-owner-segregated data under /owner-data/{owner_id}, plus a
     /insight/{owner_id} that derives a summary over a data owner's records.

The launcher injects PRIVASYS_CONTAINER_NAME and PRIVASYS_CONTAINER_TOKEN;
the manager middleware enforces (loopback + token + name) before honouring
SDK callbacks (the attestation-extensions commit below).
"""

import base64
import hashlib
import http.client
import http.server
import json
import os
import re
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

# ── Paths on the per-app sealed volume ───────────────────────────────
_DATA_DIR = Path("/data")
_KEY_PATH = _DATA_DIR / "api_key"
_STORE_DIR = _DATA_DIR / "store"            # general app data / datasets
_OWNERS_DIR = _DATA_DIR / "owners"          # data-owner-segregated data

# Keys/owner-ids are path components on the sealed volume — keep them to
# a safe charset so they can never escape their namespace.
_SAFE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

_MANAGER_HOST = "127.0.0.1"
_MANAGER_PORT = 9443

# Bumped per release so the deployed measurement (image digest at OID 3.2)
# changes and versions are distinguishable at runtime via /version.
APP_VERSION = "3.0.0"

_PORT = int(os.environ.get("PORT", "8080"))  # platform assigns a host-net port
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
            "POST", path, body=json.dumps(body),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {_TOKEN}"},
        )
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _do_configure(api_key: str) -> None:
    """Persist the secret and commit its hash to the RA-TLS leaf.

    No freeze bookkeeping here: returning 2xx from /configure is what lifts
    the manager's gate. We deliberately do NOT call config-complete.
    """
    if not api_key:
        raise ValueError("api_key must be non-empty")

    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _KEY_PATH.write_text(api_key)
    os.chmod(_KEY_PATH, 0o600)

    # Commit SHA-256(api_key) to the next per-container RA-TLS leaf so
    # verifying clients can prove the app saw exactly the delivered key
    # without ever seeing it. This is an attestation feature, not freeze
    # logic.
    digest = hashlib.sha256(api_key.encode("utf-8")).digest()
    status, body = _post_to_manager(
        f"/api/v1/containers/{_NAME}/attestation-extensions",
        {"oid": "1.3.6.1.4.1.65230.3.5.1",
         "value_b64": base64.standard_b64encode(digest).decode("ascii")},
    )
    if status >= 300:
        raise RuntimeError(f"manager attestation-extensions: {status} {body!r}")


# ── Stateful-data helpers ────────────────────────────────────────────

def _safe(component: str) -> bool:
    return bool(_SAFE.match(component or ""))


def _write_value(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    os.chmod(path, 0o600)


def _list_keys(d: Path) -> list[str]:
    try:
        return sorted(p.name for p in d.iterdir() if p.is_file())
    except FileNotFoundError:
        return []


# ── Action: process (long-running, progress-tracked) ─────────────────
# A tiny simulated job so the portal/CLI can exercise the progress channel
# declared in the manifest (GET /actions/process/status).
_JOB_LOCK = threading.Lock()
_JOB = {"state": "idle", "progress": 0.0, "message": "", "dataset": ""}


def _run_process(dataset: str) -> None:
    steps = 10
    for i in range(1, steps + 1):
        time.sleep(0.5)
        with _JOB_LOCK:
            if _JOB["state"] != "running":
                return
            _JOB["progress"] = i / steps
            _JOB["message"] = f"processing {dataset} ({i}/{steps})"
    with _JOB_LOCK:
        _JOB.update(state="done", progress=1.0,
                    message=f"processed dataset {dataset!r}")


def _start_process(dataset: str) -> dict:
    with _JOB_LOCK:
        if _JOB["state"] == "running":
            return {"error": "a job is already running", "state": "running"}
        _JOB.update(state="running", progress=0.0,
                    message=f"starting {dataset}", dataset=dataset)
    threading.Thread(target=_run_process, args=(dataset,), daemon=True).start()
    with _JOB_LOCK:
        return dict(_JOB)


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length) if length else b""

    def _json_body(self) -> tuple[dict, str | None]:
        try:
            return json.loads(self._read_body() or b"{}"), None
        except json.JSONDecodeError:
            return {}, "invalid JSON body"

    # ── GET ──────────────────────────────────────────────────────────
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/health":
            self._json(200, {"status": "healthy"})
        elif path == "/version":
            self._json(200, {"version": APP_VERSION})
        elif path == "/protected":
            try:
                key = _KEY_PATH.read_text()
            except FileNotFoundError:
                self._json(500, {"error": "api_key file missing"})
                return
            self._json(200, {"status": "ok", "api_key_length": len(key)})
        elif path == "/datasets":
            # Dynamic enum source for the `process` action.
            self._json(200, {"available": _list_keys(_STORE_DIR)})
        elif path == "/actions/process/status":
            with _JOB_LOCK:
                self._json(200, dict(_JOB))
        elif path == "/":
            self._json(200, {"status": "ok", "name": _NAME, "version": APP_VERSION})
        elif path.startswith("/store/"):
            self._get_store(path[len("/store/"):])
        elif path == "/store":
            keys = _list_keys(_STORE_DIR)
            self._json(200, {"keys": keys, "count": len(keys)})
        elif path.startswith("/owner-data/"):
            self._get_owner_data(path[len("/owner-data/"):])
        elif path.startswith("/insight/"):
            self._get_insight(path[len("/insight/"):])
        else:
            self._json(404, {"error": "not found"})

    def _get_store(self, key: str) -> None:
        if not _safe(key):
            self._json(400, {"error": "invalid key"})
            return
        try:
            value = (_STORE_DIR / key).read_bytes()
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
            keys = _list_keys(_OWNERS_DIR / owner_id)
            self._json(200, {"owner_id": owner_id, "keys": keys, "count": len(keys)})
            return
        key = parts[1]
        if not _safe(key):
            self._json(400, {"error": "invalid key"})
            return
        try:
            value = (_OWNERS_DIR / owner_id / key).read_bytes()
        except FileNotFoundError:
            self._json(404, {"error": "key not found"})
            return
        self._json(200, {"owner_id": owner_id, "key": key,
                         "value": value.decode("utf-8", "replace")})

    def _get_insight(self, owner_id: str) -> None:
        """Derive a summary insight over a data owner's stored data."""
        if not _safe(owner_id):
            self._json(400, {"error": "invalid owner_id"})
            return
        owner_dir = _OWNERS_DIR / owner_id
        records = total_bytes = longest = 0
        fingerprint = hashlib.sha256()
        try:
            files = sorted(p for p in owner_dir.iterdir() if p.is_file())
        except FileNotFoundError:
            files = []
        for p in files:
            blob = p.read_bytes()
            records += 1
            total_bytes += len(blob)
            longest = max(longest, len(blob))
            fingerprint.update(p.name.encode("utf-8"))
            fingerprint.update(blob)
        self._json(200, {
            "owner_id": owner_id, "app_version": APP_VERSION,
            "insight": {"records": records, "total_bytes": total_bytes,
                        "longest_value_bytes": longest,
                        "fingerprint": fingerprint.hexdigest()},
        })

    # ── POST ─────────────────────────────────────────────────────────
    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/configure":
            self._configure()
        elif path == "/actions/process":
            self._action_process()
        # status/source tools are reachable over the unary /rpc relay, which
        # POSTs; accept POST on the read endpoints too (body ignored).
        elif path == "/datasets":
            self._json(200, {"available": _list_keys(_STORE_DIR)})
        elif path == "/actions/process/status":
            with _JOB_LOCK:
                self._json(200, dict(_JOB))
        elif path == "/store":
            self._put_store_body()
        elif path == "/fetch":
            self._fetch_body()
        elif path.startswith("/store/"):
            self._put_store(path[len("/store/"):])
        elif path.startswith("/owner-data/"):
            self._put_owner_data(path[len("/owner-data/"):])
        else:
            self._json(404, {"error": "not found"})

    def _configure(self) -> None:
        payload, err = self._json_body()
        if err:
            self._json(400, {"error": err})
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
        # A plain 2xx is what lifts the manager's freeze gate.
        self._json(200, {"status": "configured"})

    def _action_process(self) -> None:
        payload, err = self._json_body()
        if err:
            self._json(400, {"error": err})
            return
        dataset = payload.get("dataset", "")
        if not isinstance(dataset, str) or not _safe(dataset):
            self._json(400, {"error": "dataset (a stored key) is required"})
            return
        if not (_STORE_DIR / dataset).is_file():
            self._json(404, {"error": f"dataset {dataset!r} not found under /store"})
            return
        result = _start_process(dataset)
        self._json(202 if "error" not in result else 409, result)

    def _put_store_body(self) -> None:
        payload, err = self._json_body()
        if err:
            self._json(400, {"error": err})
            return
        key, value = payload.get("key"), payload.get("value")
        if not isinstance(key, str) or not _safe(key):
            self._json(400, {"error": "invalid key"})
            return
        if not isinstance(value, str):
            self._json(400, {"error": "value (string) is required"})
            return
        _write_value(_STORE_DIR / key, value.encode("utf-8"))
        self._json(200, {"status": "stored", "key": key, "bytes": len(value)})

    def _fetch_body(self) -> None:
        payload, err = self._json_body()
        if err:
            self._json(400, {"error": err})
            return
        key = payload.get("key")
        if not isinstance(key, str) or not _safe(key):
            self._json(400, {"error": "invalid key"})
            return
        try:
            value = (_STORE_DIR / key).read_bytes()
        except FileNotFoundError:
            self._json(404, {"error": "key not found"})
            return
        self._json(200, {"key": key, "value": value.decode("utf-8", "replace")})

    def _put_store(self, key: str) -> None:
        if not _safe(key):
            self._json(400, {"error": "invalid key"})
            return
        payload, err = self._json_body()
        if err:
            self._json(400, {"error": err})
            return
        value = payload.get("value")
        if not isinstance(value, str):
            self._json(400, {"error": "value (string) is required"})
            return
        _write_value(_STORE_DIR / key, value.encode("utf-8"))
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
        payload, err = self._json_body()
        if err:
            self._json(400, {"error": err})
            return
        value = payload.get("value")
        if not isinstance(value, str):
            self._json(400, {"error": "value (string) is required"})
            return
        _write_value(_OWNERS_DIR / owner_id / key, value.encode("utf-8"))
        self._json(200, {"status": "stored", "owner_id": owner_id,
                         "key": key, "bytes": len(value)})

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", _PORT), Handler)
    print(f"container-app-example-with-config listening on :{_PORT} "
          f"(name={_NAME or '<unset>'}, version={APP_VERSION})")
    server.serve_forever()
