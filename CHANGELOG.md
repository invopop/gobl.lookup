# Changelog

## [Unreleased]

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
