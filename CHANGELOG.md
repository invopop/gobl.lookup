# Changelog

## [Unreleased]

### Changed

- Persistence now uses the shared [`github.com/invopop/couch`](https://github.com/invopop/couch) library: `models.Registration` embeds `couch.Model` (gaining `created_at`/`updated_at` and revision handling), and the CouchDB store uses `couch.Client`/`couch.Store`/`couch.Fetch` and a `couch.Design` for the by-UUID view. The registration database is the couch client's prefix (`COUCHDB_DATABASE`).
- Configuration is now read from the environment (`CONFIG_DIR`, `COUCHDB_URL` or the split `COUCHDB_SCHEME/HOST/PORT/USERNAME/PASSWORD`, `COUCHDB_DATABASE`, `HTTP_PORT`/`PORT`, `PUBLIC_BASE_URL`, `LOG_JSON`) so the service can be configured — and its CouchDB password injected from a secret — the way the cluster provides config. The equivalent CLI flags still work and override the environment. Env var names match the sibling services (silo/access).
- Removed the Fly.io deployment (`fly.toml`); the `Dockerfile` (small, static, non-root) is the deployment artifact for the Kubernetes cluster.
- Restructured the codebase along the standard Invopop layered architecture (cf. `silo`, `access`): business logic now lives in `internal/domain` (orchestrated by `domain.Setup`), data structures in `internal/domain/models`, persistence in `internal/domain/repos`, outbound delivery in `internal/domain/delivery`, and the HTTP layer in `internal/interfaces/web`. The registration and verification flows moved out of the HTTP handlers into the `domain.Registrations` service; handlers are now thin adapters that map domain errors onto HTTP status codes. No change to the wire protocol, endpoints, CouchDB schema, or CLI.

### Added

- `gobl.lookup`: initial implementation of a GOBL Net Authority registry service. Accepts party registrations on the standard `/.well-known/gobl/inbox` endpoint, countersigns the envelope with `head.ScopeRegistered`, and posts the result back to the sender's own `/inbox`. No new protocol endpoints — only existing GOBL Net primitives.
- CouchDB-backed registry (`github.com/go-kivik/kivik/v4`). One database (`gobl-lookup` by default), one document per registered address (`registration:<address>`), CouchDB MVCC handles re-registrations as revisions. A `parties/by_uuid` view supports the `/parties/<uuid>` immutable lookup.
- HTTP endpoints: `POST /.well-known/gobl/inbox` (registration entry), `POST /.well-known/gobl/who`, `GET /.well-known/gobl/keys/<kid>`, `GET /.well-known/jwks.json`, `GET /parties/<address|uuid>` (public record), `GET /healthz`.
- `head.Link` discovery hint stamped on the countersigned envelope pointing at `<public-base-url>/parties/<uuid>`. Header links are mutable post-signature — the link is a discovery hint, not part of the trust claim.
- CLI:
  - `gobl.lookup init <domain>` scaffolds the lookup's keypair + party.json + keys/<kid>.json under `--config-dir`.
  - `gobl.lookup serve --config-dir … --couchdb …` runs the HTTPS server (HTTP-only terminator in v1; deploy behind a TLS proxy).
  - `gobl.lookup verify <address>` re-countersigns the registered envelope with `head.ScopeVerified` and re-delivers to the sender's inbox.
  - `gobl.lookup version` prints the service + core gobl version.
- SSRF defense on outbound delivery: refuses to dial loopback / private / link-local / multicast / unspecified IPs. Same policy as `gobl/net`'s default `HTTPFetcher`.
- Async delivery: the `/inbox` POST returns `202 Accepted` once the record is persisted; the actual POST to the sender's `/inbox` happens in a background goroutine. Failures are recorded on the registry record (`Status: failed`, `LastDeliveryError`).
- Re-registration semantics: a fresh registration for an existing address drops `scope` back to `registered` and clears `verified_at` (party data may have changed since the last KYC).

### Security

- Inbox `aud` is required: an envelope POSTed to `/inbox` MUST be signed with `aud == gobl:lookup.<domain>`. Envelopes without an audience, or bound to a different audience, are rejected with 401 (replay protection — mirrors the recent gobl.dev inbox tightening).
- Registration envelope MUST contain an `org.Party` document; anything else is rejected with 422.
