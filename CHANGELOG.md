# Changelog

## [Unreleased]

### Changed

- Verification is now list-driven and automatic: the registry accepts a configured set of verification providers (`--verifiers` / `VERIFIERS`), and a registration or renewal arriving with a valid countersignature from one of them is verified on arrival — the countersignature is cryptographically checked against the provider's published key before being named (an unreachable key endpoint registers unverified and logs `inbox.auto_verify_unavailable`; the derivation re-runs on renewal). `gobl.lookup verify <address>` loses the `--verifier` flag and becomes a recovery command that re-derives the verifier from the stored envelope, e.g. after a provider is added to the accepted list. The discovery link stamped on countersigned envelopes uses the standard `verification` category (the previous `authority` value failed envelope validation on re-signing).

- Transient failures now answer `503 Service Unavailable` instead of
  a definitive 4xx: an unreachable requester key endpoint during
  token verification (log reason `token_unavailable`), and an
  unreachable sender `/who` during registration eligibility (log
  reason `who_unavailable`) — senders stop retrying on 4xx, so
  outages must not permanently reject. Outbound deliveries likewise
  distinguish retryable conditions (transport failures, 429, 5xx →
  `net.ErrUnavailable`) from definitive inbox rejections.

- Every Authority countersignature now carries a 90-day `exp` claim; parties renew by re-registering before it passes. A renewal with an unchanged party document (same digest) is countersigned with the party's current `verifier` claim — verified stays verified — while changed party data drops the verifier and clears `verified_at`.
- The `scope` claim is replaced by structural verification (spec §5.3): a registration countersignature alone asserts a registered identity, and `gobl.lookup verify` re-countersigns with a `verifier` claim naming the KYC/KYB authority. `--verifier` names an external verifying authority (its own countersignature must already be on the stored envelope); the default is the lookup itself, whose single countersignature carries both attestations. The verifier signature's `exp` is independent of the 90-day registration cycle, so verifications can be much longer-lived. `Registration.Verifier` replaces the stored `scope` field.
- `/.well-known/gobl/who` is now a `GET` serving the lookup's self-signed party envelope (signed once per process), replacing the authenticated `POST` exchange. Together with `/inbox` it requires a bearer request token (spec §5.5): the requester's token is verified against its published key, audience, and freshness window, and requests without a valid token are rejected with `401` (`auth.rejected` log reasons `token_missing`/`token_invalid`/`token_expired`). The response is served with `Cache-Control: private, max-age=300`; authenticated requests are logged with the requester address as the request audit log. Key discovery and `/parties` stay open.
- Outbound requests authenticate as the lookup itself: the sender `GET /who` eligibility check and countersigned-envelope deliveries carry bearer request tokens. A registrant answering its own `/who` with `202` (deferred disclosure) is rejected with `403` — senders must disclose openly to register.
- Registration now requires the sender to serve its own public identity: the inbox resolves `GET /who` on the sender's address (re-fetching its published key) before countersigning. A `204 No Content` — a receive-only account — or an unresolvable identity rejects the registration with `403 Forbidden`.
- Allow-list support (`allow.json`, `models.Identity.Allow`) is removed; the sender `/who` check is the gate on registrations.
- Updated to the current `gobl` net API: `Envelope.Sign` options (`head.WithIssuer`/`WithAudience`/`WithVerifier`) and `net.Client.Who`. Signed `iss`/`aud`/`verifier` claims carry bare GOBL Net addresses (FQDNs) rather than `gobl:` URIs; the scheme remains only on `org.Endpoint` URIs.
- Identity key files under `keys/` no longer need to be named after their kid — the kid is read from the JWK itself, and any `*.json` file is accepted (`Init` still writes `<kid>.json`). This lets a deployment mount the published key at a fixed path (e.g. `keys/public.json`) without encoding the kid in the filename.
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
  - `gobl.lookup serve --config-dir … --couchdb …` runs the HTTP server (terminates HTTP only in v1; deploy behind a TLS proxy).
  - `gobl.lookup verify <address>` re-countersigns the registered envelope with `head.ScopeVerified` and re-delivers to the sender's inbox.
  - `gobl.lookup version` prints the service + core gobl version.
- SSRF defense on outbound delivery: refuses to dial loopback / private / link-local / multicast / unspecified IPs. Same policy as `gobl/net`'s default `HTTPFetcher`.
- Async delivery: the `/inbox` POST returns `202 Accepted` once the record is persisted; the actual POST to the sender's `/inbox` happens in a background goroutine. Failures are recorded on the registry record (`Status: failed`, `LastDeliveryError`).
- Re-registration semantics: a fresh registration for an existing address drops `scope` back to `registered` and clears `verified_at` (party data may have changed since the last KYC).

### Security

- Inbox `aud` is required: an envelope POSTed to `/inbox` MUST be signed with `aud` equal to the lookup’s address. Envelopes without an audience, or bound to a different audience, are rejected with 401 (replay protection — mirrors the recent gobl.dev inbox tightening).
- Registration envelope MUST contain an `org.Party` document; anything else is rejected with 422.
