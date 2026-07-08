# gobl.lookup

A reference [GOBL Net](https://github.com/invopop/gobl/blob/net/net/README.md)
**Authority** registry service. Accepts party registrations from
GOBL Net nodes, countersigns each party envelope with an
Authority-level scope (`registered` → `verified` after KYC), and
posts the countersigned envelope back to the sender's own inbox.

> ⚠️ **EXPERIMENTAL** — GOBL Net is under active development. The
> wire protocol may change without notice.

Released under the Apache 2.0
[LICENSE](https://github.com/invopop/gobl.lookup/blob/main/LICENSE),
Copyright 2026 [Invopop S.L.](https://invopop.com).

## How registration works

1. A GOBL Net node (e.g. a `gobl.dev` operator at
   `alice.example`) signs an envelope containing its `org.Party`
   and POSTs it to lookup's `/.well-known/gobl/inbox`. The
   envelope's signed `iss=gobl:alice.example`,
   `aud=gobl:lookup.gobl.org`.
2. Lookup verifies the signature, persists the envelope in
   CouchDB, countersigns it with an Authority signature
   (`iss=gobl:lookup.gobl.org`, `aud=gobl:alice.example`,
   `scope=registered`), and POSTs the **countersigned** envelope
   back to `https://alice.example/.well-known/gobl/inbox`.
3. Alice publishes the countersigned envelope on her `/who`. Any
   GOBL Net verifier can now confirm that lookup has attested to
   her registration via `net.Client.VerifyAuthority`.

No new protocol endpoints — registration uses the standard GOBL
Net `/inbox` POST in both directions.

## Architecture

The code follows the standard Invopop layered layout (cf. `silo`,
`access`):

```
internal/
  config/            runtime configuration (populated from CLI flags)
  domain/            business logic, orchestrated by domain.Setup
    domain.go          Setup: wires repos + services together
    identity.go        Identity service: countersign, /who exchange, keys
    registrations.go   Registrations service: register, verify, find
    errors.go          typed domain errors (mapped to HTTP statuses)
    models/            data structures (Registration, Identity)
    repos/             persistence (CouchDB + in-memory; identity loader)
    delivery/          outbound Sender (HTTP POST to a subject's inbox)
  interfaces/
    web/             HTTP transport: thin handlers over domain.Setup
cmd/gobl.lookup/     CLI (init / serve / verify / version)
```

Handlers in `interfaces/web` parse the request, delegate to a domain
service, and translate `domain.Error` kinds into HTTP status codes.
The domain never imports the transport layer.

## Endpoints

| Method | Path                                | Purpose                                                  |
|--------|-------------------------------------|----------------------------------------------------------|
| POST   | `/.well-known/gobl/inbox`           | Registration entry — must carry an `org.Party` document. |
| POST   | `/.well-known/gobl/who`             | Authenticated mutual party exchange (lookup's identity). |
| GET    | `/.well-known/gobl/keys/<kid>`      | Single published key.                                    |
| GET    | `/.well-known/jwks.json`            | Bulk JWK Set (for jwt.io-style tooling).                 |
| GET    | `/parties/<address>`                | Public registration record by address.                   |
| GET    | `/parties/<uuid>`                   | Public registration record by envelope UUID.             |
| GET    | `/healthz`                          | Liveness check.                                          |

## Quickstart (local dev)

```bash
# 1. CouchDB
docker compose up -d couchdb

# 2. Scaffold the lookup identity
go run ./cmd/gobl.lookup init --config-dir ./dev/lookup.local lookup.local

# 3. Serve
go run ./cmd/gobl.lookup serve \
    --config-dir ./dev/lookup.local \
    --couchdb http://admin:pass@localhost:5984 \
    --http-port 8081 \
    --public-base-url http://localhost:8081
```

Then from a `gobl.dev` node, point `gobl net send` at lookup with
the `--insecure` flag (HTTP-only, dev-only). The countersigned
envelope lands in your node's `inbox/` directory.

## CouchDB schema

One database (`gobl-lookup` by default). One document per
registered address with id `registration:<address>`:

```json
{
  "_id": "registration:alice.example",
  "address": "alice.example",
  "scope": "registered",
  "status": "delivered",
  "incoming_envelope_uuid": "...",
  "received_at": "2026-06-07T...",
  "envelope": { ... full countersigned envelope ... },
  "delivery_attempts": 1,
  "last_delivery_at": "2026-06-07T...",
  "verified_at": null
}
```

The `_design/parties` design doc exposes a `by_uuid` view that
backs the `/parties/<uuid>` lookup. CouchDB MVCC revisions
preserve the audit trail across re-registrations.

## CLI

| Command                        | Purpose                                                                                 |
|--------------------------------|-----------------------------------------------------------------------------------------|
| `gobl.lookup init <domain>`    | Scaffold keypair + `party.json` + `keys/<kid>.json`.                                    |
| `gobl.lookup serve`            | Run the HTTP server (terminates HTTP only; deploy behind a TLS proxy).                   |
| `gobl.lookup verify <address>` | Bump a registration to `head.ScopeVerified` after out-of-band KYC and re-deliver.       |
| `gobl.lookup version`          | Print service + core gobl versions.                                                     |

The top-level `--json` flag switches operator logs from text to
JSON on stderr.

## Configuration

`serve` and `verify` read their configuration from the environment
(the mechanism the cluster uses to inject config and secrets); the
equivalent flags override the environment for local use.

| Env var             | Flag                 | Default       | Purpose                                                             |
|---------------------|----------------------|---------------|--------------------------------------------------------------------|
| `CONFIG_DIR`        | `--config-dir`       | —             | Directory holding the identity (`private.jwk` + `party.json` + `keys/`). |
| `COUCHDB_URL`       | `--couchdb`          | —             | Full CouchDB URL. Overrides the split `COUCHDB_*` parts below.      |
| `COUCHDB_SCHEME`    | —                    | `http`        | CouchDB scheme (used when `COUCHDB_URL` is unset).                  |
| `COUCHDB_HOST`      | —                    | —             | CouchDB host, e.g. `couchdb-svc.default`.                           |
| `COUCHDB_PORT`      | —                    | `5984`        | CouchDB port.                                                       |
| `COUCHDB_USERNAME`  | —                    | `admin`       | CouchDB user.                                                       |
| `COUCHDB_PASSWORD`  | —                    | —             | CouchDB password (inject from a secret).                           |
| `COUCHDB_DATABASE`  | `--couchdb-database` | `gobl-lookup` | Database name.                                                      |
| `HTTP_PORT`/`PORT`  | `--http-port`        | `8080`        | HTTP listen port (`HTTP_PORT` wins over `PORT`).                    |
| `PUBLIC_BASE_URL`   | `--public-base-url`  | `https://<domain>` | Canonical URL for `/parties/<uuid>` discovery links.          |
| `LOG_JSON`          | `--json`             | `false`       | Emit structured JSON logs on stderr.                               |

Supply the CouchDB connection either as a single `COUCHDB_URL`
(handy for local dev, e.g. `http://admin:pass@localhost:5984`) or via
the split `COUCHDB_*` parts (the cluster convention, so the password
arrives from a secret independently of the host).

## Operations

- **Re-registration**: a fresh registration for an existing
  address resets `scope` to `registered` and clears `verified_at`.
  Verifying again requires another `gobl.lookup verify <address>`
  call. Audit trail lives in CouchDB revisions.
- **Delivery failures**: the inbox handler responds `202` once the
  record is persisted; delivery to the sender's `/inbox` happens
  asynchronously. Failures land on `Record.LastDeliveryError`;
  re-running `gobl.lookup verify` retries.
- **Allow-list**: the optional `<config-dir>/allow.json` (an array
  of addresses) gates `/inbox` and `/who` requests. Empty / absent
  means accept any verified caller — the right default for a
  public registry.

## Deployment

The repo ships with a `Dockerfile` producing a small, static,
non-root image suitable for running on Kubernetes. Build and run it
directly:

```bash
docker build -t gobl.lookup .
docker run --rm -p 8080:8080 \
    -v "$PWD/dev/lookup.local:/config:ro" \
    -e CONFIG_DIR=/config \
    -e COUCHDB_HOST=couchdb -e COUCHDB_USERNAME=admin -e COUCHDB_PASSWORD=pass \
    -e PUBLIC_BASE_URL=https://lookup.example \
    gobl.lookup serve
```

The server listens on `8080` by default (no `HTTP_PORT` needed).

In a cluster, mount the identity (`private.jwk` + `party.json` +
`keys/`) into `CONFIG_DIR` and inject the `COUCHDB_*` values (password
from a secret) as environment variables — see [Configuration](#configuration).

## License

See [LICENSE](LICENSE).
