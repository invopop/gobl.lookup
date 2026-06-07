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
| `gobl.lookup serve`            | Run the HTTPS server (HTTP-only termination; deploy behind a TLS proxy).                |
| `gobl.lookup verify <address>` | Bump a registration to `head.ScopeVerified` after out-of-band KYC and re-deliver.       |
| `gobl.lookup version`          | Print service + core gobl versions.                                                     |

The top-level `--json` flag switches operator logs from text to
JSON on stderr.

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

The repo ships with a `Dockerfile` and a `fly.toml` mirroring the
sibling `gobl.dev` shape. Fly deploys to the `gobl-lookup` app in
the `cdg` region by default; adjust the toml for your environment.

## License

See [LICENSE](LICENSE).
