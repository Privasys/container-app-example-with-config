# Container App Example (with config)

A minimal Python container that is the reference for the Privasys
**typed config + actions** capabilities on `enclave-os-virtual` (TDX).
The image-bound manifest (`privasys.json`) declares a `config` block and
an `actions` list; the portal, CLI, and MCP render and drive them with no
app-specific platform code.

## Configure-then-freeze is enforced at the routing layer, not in the app

Config and actions are role-tagged tools on the same schema/RPC surface the
API Test tab uses (each is invoked via unary `/rpc/{name}`). The manifest
declares a tool with `role: "config"`:

```json
{ "name": "configure", "role": "config", "endpoint": "/configure",
  "inputSchema": { "type": "object",
    "properties": { "api_key": { "type": "string",
                                 "x-privasys": { "secret": true, "label": "API key" } } },
    "required": ["api_key"] } }
```

On deploy the enclave manager keeps **every** path except the configure
endpoint at HTTP 503 ("awaiting initial configuration"), and lifts the
gate **automatically on the first 2xx response** from `/configure`. The
gate re-arms on every restart.

This app contains **no** freeze flag, **no** 503 gating of its own, and it
does **not** call `config-complete`. The gate lives entirely in the
manager. (The Dockerfile `LABEL org.privasys.config_api="POST /configure"`
is retained for backward compatibility while the deploy pipeline migrates
to deriving the gate from the manifest `config` block.)

| Endpoint | Before configure | After configure |
|----------|------------------|-----------------|
| `POST /configure` | accepts the API key (lifts the gate) | replaces the key |
| everything else | **503** (manager) | served normally |

## Configure flow

1. The launcher injects `PRIVASYS_CONTAINER_NAME` and
   `PRIVASYS_CONTAINER_TOKEN`. The manager only honours SDK callbacks that
   originate on loopback, present the token, and target this container's
   `{name}`.
2. The owner submits `{"api_key": "<secret>"}` to `/configure` (via the
   portal Configure tab / CLI / the management-service relay). The app:
   1. Writes the key to `/data/api_key` (the per-app sealed volume).
   2. Computes `SHA-256(api_key)` and POSTs it to
      `…/api/v1/containers/{name}/attestation-extensions`, so the next
      per-container RA-TLS leaf advertises the configured-secret hash
      under OID `1.3.6.1.4.1.65230.3.5.1` (an attestation feature, not
      freeze logic).
   3. Returns `200` — which is what lifts the manager gate.
3. Verifying clients can now prove they are talking to a TDX container
   that saw exactly the key that was delivered, without seeing the key.

## Typed action: `process`

A tool with `role: "action"` whose input has a **dynamic enum** source and a
tool-level **progress** channel, both referencing other tools by name:

```json
{ "name": "process", "role": "action", "endpoint": "/actions/process",
  "inputSchema": { "type": "object",
    "properties": { "dataset": { "type": "string",
      "x-privasys": { "source": { "tool": "datasets", "select": "available" } } } },
    "required": ["dataset"] },
  "x-privasys": { "progress": { "tool": "process_status",
    "stateField": "state", "progressField": "progress",
    "terminal": { "success": ["done"], "failure": ["failed"] } } } }
```

- `datasets` (role `status`, `/datasets`) returns `{"available": [<stored keys>]}`
  — the live source for the dataset dropdown.
- `process` (`/actions/process`) `{"dataset": "<key>"}` starts a short job (`202`).
- `process_status` (role `status`, `/actions/process/status`) returns
  `{state, progress, message}`; the portal renders a progress bar until `state`
  is `done`/`failed`.

All four are reachable Postman-style in the API Test tab and over MCP, since
they are ordinary tools; the Configure tab and Manage panel are just native
renderings of the `config`- and `action`-role tools.

## Stateful data (drives the upgrade-approval scenarios)

All data lives on `/data` (the per-app encrypted volume). Two namespaces,
gated by two different key-holders when the enclave or the app is
upgraded:

| Namespace | Endpoint | Gated on upgrade by |
|-----------|----------|---------------------|
| **App data**        | `POST /store {key,value}`, `GET /store/{key}` | the **app owner** approves the new measurement; the app storage key is released, so `/store` carries forward |
| **Data-owner data** | `POST /owner-data/{owner_id}/{key}`, `GET …` | **each data owner** independently approves before their slice is readable |

`GET /insight/{owner_id}` derives a summary over a data owner's records.

## Restart

The persisted key in `/data/api_key` survives, but the manager re-arms the
freeze on restart, so the owner re-submits the configuration before
traffic flows. Persisted attestation extensions on the leaf survive too.

## Local smoke test

```bash
docker build -t privasys/container-app-example-with-config .
docker run --rm -e PRIVASYS_CONTAINER_NAME=demo \
                -e PRIVASYS_CONTAINER_TOKEN=$(openssl rand -hex 32) \
                -p 8080:8080 privasys/container-app-example-with-config
```

`/configure` will fail with a connection error outside the enclave (no
manager on `127.0.0.1:9443`); use the platform e2e harness for the full
flow.
