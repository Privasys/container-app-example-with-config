# Container App Example

A minimal Python container that exercises the Privasys
**configure-then-freeze** pattern on `enclave-os-virtual` (TDX).

## What it shows

| Endpoint               | Frozen state | After `/configure` |
|------------------------|--------------|--------------------|
| `GET /health`          | 200 healthy  | 200 healthy        |
| `POST /configure`      | accepts the API key | replaces the key |
| `GET /protected`       | **503**      | 200 + key length   |
| `GET /`                | **503**      | 200                |
| `POST /store/{key}`    | **503**      | store general app data |
| `GET /store/{key}`     | **503**      | read it back        |
| `POST /owner-data/{owner_id}/{key}` | **503** | store data-owner data |
| `GET /owner-data/{owner_id}/{key}`  | **503** | read it back        |
| any other              | **503** / 404 | 404               |

The freeze is enforced inside the container itself via an in-memory
`_CONFIGURED` flag that always starts `False` and is reset on every
restart of the process.

## Configure flow

1. Deploy the container. The launcher injects two environment
   variables: `PRIVASYS_CONTAINER_NAME` and
   `PRIVASYS_CONTAINER_TOKEN`. Hosts and the wider network never see
   the token — it is bound to a single container instance and the
   manager only honours requests that:
   - originate on the loopback interface (host-net containers share
     `127.0.0.1` with the manager), AND
   - present the token via `Authorization: Bearer …`, AND
   - target the path `/api/v1/containers/{name}/...` whose `{name}`
     matches the token-bound container.
2. The deployer POSTs `{"api_key": "<secret>"}` to `/configure`.
   The container:
   1. Writes the key to `/data/api_key` (the per-app sealed volume).
   2. Computes `SHA-256(api_key)`.
   3. POSTs the hash to
      `http://127.0.0.1:9443/api/v1/containers/{name}/attestation-extensions`
      with the bearer token. The manager records the extension under
      OID `1.3.6.1.4.1.65230.3.5.1` and re-issues the per-container
      RA-TLS leaf certificate so the next handshake advertises the
      configured-secret hash.
   4. POSTs to `…/config-complete` to lift the freeze on the manager
      side too.
   5. Sets the in-memory `_CONFIGURED = True`.
3. Subsequent requests to `/protected` succeed; verifying clients
   can prove they're talking to a TDX container that saw exactly the
   API key they delivered.

## Stateful data (drives the upgrade-approval scenarios)

All data lives on `/data`, the per-app encrypted volume whose DEK is
reconstructed from the Enclave Vault constellation at boot (the platform
never sees the key). Two namespaces, gated by two different key-holders
when the enclave (mini/virtual) or the app itself is upgraded:

| Namespace | Endpoint | Gated on upgrade by |
|-----------|----------|---------------------|
| **App data**        | `POST/GET /store/{key}` | the **app owner** — approves the new measurement; the app storage key is released to it, so `/store` carries forward |
| **Data-owner data** | `POST/GET /owner-data/{owner_id}/{key}` | **each data owner** independently — approves the new measurement before their slice is readable; a data owner who declines keeps their data locked to the old version |

Both take/return `{"value": "<string>"}`. `GET /store` and
`GET /owner-data/{owner_id}` list keys. In the full model each data
owner's slice is wrapped with that owner's vault key (Phase G
data-owner-keys); here the app provides the data surface and segregation,
and the per-owner key-wrapping + approval gating is enforced by the
platform/vault.

## Restart

The in-memory flag is reset on every container restart. The persisted
key in `/data/api_key` survives, but the runtime treats the app as
unconfigured until the deployer hits `/configure` again. Persisted
attestation extensions on the leaf certificate also survive the
restart, so verifying clients keep working without manual
intervention.

## Dockerfile contract

The Dockerfile must declare:

```dockerfile
LABEL org.privasys.config_api="POST /configure"
```

so that the Privasys deploy pipeline populates the per-app
`config_api` field. Without this label the runtime cannot know the
app is going to self-freeze and no 503s would be enforced
upstream.

## Local smoke test

```bash
docker build -t privasys/container-app-example .
docker run --rm -e PRIVASYS_CONTAINER_NAME=demo \
                -e PRIVASYS_CONTAINER_TOKEN=$(openssl rand -hex 32) \
                -p 8080:8080 privasys/container-app-example
```

You can hit `/health` (200), `/protected` (503), then `/configure`
will fail with a connection error because there is no manager on
`127.0.0.1:9443` outside of the enclave host. To exercise the full
flow end-to-end use the platform e2e test harness.
