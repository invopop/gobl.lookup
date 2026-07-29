# gobl.lookup

A reference [GOBL Net](https://github.com/invopop/gobl/blob/net/net/README.md)
**Authority** registry service. Accepts party registrations from
GOBL Net nodes, countersigns each party envelope as the network's
default registration Authority (adding a `verifier` claim once the
party passes KYC/KYB), and posts the countersigned envelope back to
the sender's own inbox.

> ⚠️ **EXPERIMENTAL** — GOBL Net is under active development. The
> wire protocol may change without notice.

Released under the Apache 2.0
[LICENSE](https://github.com/invopop/gobl.lookup/blob/main/LICENSE),
Copyright 2026 [Invopop S.L.](https://invopop.com).

## How registration works

1. A GOBL Net node (e.g. a `gobl.dev` operator at
   `alice.example`) signs an envelope containing its `org.Party`
   and POSTs it to lookup's `/.well-known/gobl/inbox`. The
   envelope's signed `iss=alice.example`,
   `aud=lookup.gobl.org` (signed claims carry bare addresses — GOBL
   Net is implied).
2. Lookup verifies the signature, then confirms the sender checks
   out as a *sending* participant: it performs `GET /who` on
   `alice.example` (re-fetching her published key in the process)
   and requires a verified, self-signed party. A `204 No Content`
   marks a receive-only account and rejects the registration with
   `403 Forbidden`.
3. Lookup persists the envelope in CouchDB, countersigns it with
   an Authority signature (`iss=lookup.gobl.org`,
   `aud=alice.example`, `exp` = 90 days
   out), and POSTs the **countersigned** envelope back to
   `https://alice.example/.well-known/gobl/inbox` as a follow-up
   message. The original POST is acknowledged with the standard
   empty `202 Accepted` used for all inbox deliveries.
4. Alice publishes the countersigned envelope on her `/who`. Any
   GOBL Net verifier can now confirm that lookup has attested to
   her registration via `net.Client.VerifyAuthority` /
   `net.Client.VerifySender`.

No new protocol endpoints — registration uses the standard GOBL
Net `/inbox` POST in both directions. Marking a registration as
verified (spec §5.3, the `verifier` claim) happens automatically
when the envelope carries a countersignature from an accepted
verification provider; the full self-service flow is specified in
[How verification works](#how-verification-works) below.

### Endorsement lifetime and renewal

Every countersignature carries a 90-day `exp` claim — verifiers
reject it after that, so parties renew by re-registering before it
passes (Let's Encrypt style). A renewal that re-submits the
**unchanged** party document (same digest) is countersigned with
the party's current `verifier` claim: verified stays verified,
while the verifier's own longer-lived countersignature (a year or
more, in the spirit of EV certificates) continues to evidence the
KYC. Submitting changed party data is a fresh registration — the
verifier is dropped and KYC must be repeated.


## How verification works

> **Status: partial.** The registry side is implemented: the
> accepted-verifier list (`--verifiers` / `VERIFIERS`), auto-verify
> on registrations carrying a provider countersignature, and the
> `gobl.lookup verify` recovery command. The web flow, email OTP,
> and verifier session hand-off are not yet implemented — see the
> gap list at the end of this section.

Verification upgrades a *registered* identity to *verified* by
adding two things to the party envelope: a countersignature from a
KYC/KYB provider ("verifier", e.g. `didit.gobl.org`), and a fresh
lookup countersignature carrying the `verifier` claim that points
at it. The registry orchestrates; the verifier performs and charges
for the actual checks; the protocol carries the results as plain
inbox deliveries.

1. **Start.** A representative of the registered party opens
   `https://lookup.gobl.org/verify/<address>`. The address MUST
   already be registered (unregistered addresses are pointed at
   the registration flow first) and its party MUST publish at
   least one email address — the flow has no other way to reach a
   human connected to the party.
2. **Email OTP.** Lookup sends a one-time code to an email chosen
   from the party's published `emails`. This does not verify the
   *business* — that is the verifier's job — it gates the flow:
   only someone with access to the party's own published mailbox
   can start (and pay for) verification, so third parties cannot
   spend a subject's verification budget or spam providers on its
   behalf. Domain control was already proven at registration by
   the signed envelope. OTP attempts are rate-limited per address.
3. **Choose a verifier.** The user picks from the registry's
   configured trusted-verifier list (the same list the registry is
   willing to name in `verifier` claims). Each entry shows the
   provider's published verification policy — which checks are
   performed, price, and countersignature lifetime — so the trust
   a receiver will later infer from the verifier's name is
   inspectable up front.
4. **Session hand-off.** Lookup POSTs the party's **stored,
   countersigned envelope** to the verifier's session API in the
   background, authenticated with a request token for
   `lookup.gobl.org` (spec §5.5). Sending the stored envelope
   pins the verification to an exact `uuid` + `dig`: the verifier
   MUST countersign those bytes, so the checks and the eventual
   signature cannot drift apart. The verifier answers with an
   opaque, single-use session URL (or an error if it cannot serve
   the party's jurisdiction); lookup redirects the user's browser
   to it. Session URLs are unguessable on purpose —
   `/verify/<address>` alone would let anyone walk into a session
   holding another party's data.
5. **The verifier's process.** On the verifier's own pages (e.g.
   `https://didit.gobl.org/...`), the user provides the company
   representative's personal contact details and payment. Payment
   is deliberately part of the KYC surface — cardholder data is
   itself a fraud signal — and keeps verification revenue entirely
   on the verifier's side: the registry stays free. From here the
   provider runs its usual process (document checks, liveness,
   registry/UBO lookups, AML screening).
6. **Countersign and return.** On success the verifier
   countersigns the envelope from step 4 (`iss=<verifier>`,
   `aud=<subject>`, `exp` a year or more — spec §5.3) and POSTs
   the envelope back to lookup's standard `/inbox` with its own
   request token. To the inbox this is an ordinary renewal: same
   digest, first signature still the subject's, one extra
   countersignature aboard. Failed or abandoned sessions simply
   never produce a countersignature; sessions expire after a few
   days and the verifier SHOULD notify lookup so the flow's status
   page can say so.
7. **Auto-verify.** When a renewal arrives carrying a valid
   countersignature from a verifier on the trusted-verifier list,
   lookup re-countersigns with `verifier=<that address>`
   automatically — the same act as `gobl.lookup verify`, without
   the operator. The stored record gains `verifier` +
   `verified_at`.
8. **Deliver and publish.** The now twice-countersigned envelope
   (subject self-signature, verifier countersignature, lookup
   countersignature naming the verifier) is delivered to the
   subject's own `/inbox` — the standard registration delivery
   path. The subject publishes it at its `/who`; only then do
   receivers see the verified status. The verify status page tells
   the user this last step is theirs.

Renewal interplay is unchanged: re-registering the identical party
document keeps the verifier claim; changed party data drops it and
the party goes through verification again (the verifier's own
countersignature attests to the *checked* data, not to future
edits).

**Implementation gaps** (in rough order):

- Policy/pricing metadata for the accepted-verifier list (the
  addresses themselves are configured via `--verifiers` /
  `VERIFIERS`, and step 7's auto-verify is implemented: a
  registration or renewal carrying a valid countersignature from an
  accepted provider is verified on arrival, with the crypto checked
  against the provider's published key first).
- The `/verify/<address>` web flow: OTP issue/check, verifier
  picker, redirect, and a status page for pending sessions.
- The verifier session API contract (step 4): create-session
  request/response shape shared with bridge implementations like
  `didit.gobl.org`, including session expiry and failure
  callbacks.
- A `head.Link` on the registration delivery pointing the subject
  at `verify/<address>`, so every registered party discovers the
  upgrade path.

## Architecture

The code follows the standard Invopop layered layout (cf. `silo`,
`access`):

```
internal/
  config/            runtime configuration (populated from CLI flags)
  domain/            business logic, orchestrated by domain.Setup
    domain.go          Setup: wires repos + services together
    identity.go        Identity service: countersign, /who identity, keys
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

| Method | Path                                | Auth  | Purpose                                                  |
|--------|-------------------------------------|-------|----------------------------------------------------------|
| POST   | `/.well-known/gobl/inbox`           | token | Registration entry — must carry an `org.Party` document. |
| GET    | `/.well-known/gobl/who`             | token | Lookup's identity (self-signed party envelope).          |
| GET    | `/.well-known/gobl/keys/<kid>`      | open  | Single published key.                                    |
| GET    | `/.well-known/jwks.json`            | open  | Bulk JWK Set (for jwt.io-style tooling).                 |
| GET    | `/parties/<address>`                | open  | Public registration record by address.                   |
| GET    | `/parties/<uuid>`                   | open  | Public registration record by envelope UUID.             |
| GET    | `/healthz`                          | open  | Liveness check.                                          |

The who and inbox endpoints require a bearer request token (spec
§5.5) minted from the caller's own published key; requests without
a valid token get `401`, and `503` when the token cannot be checked
because the issuer's key endpoint is unreachable (retry). The token's issuer may be a trusted
intermediary transmitting on the registrant's behalf — the
registration subject always comes from the envelope's own
signature. Key discovery stays open (it is what makes token
verification possible), and `/parties` remains an open directory of
registered — hence deliberately public — identities. The lookup's
own outbound requests (the sender `GET /who` eligibility check and
countersigned-envelope deliveries) authenticate the same way, as
`lookup.gobl.org`. Authenticated requests are logged with the
requester address, forming the request audit log.

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

GOBL Net clients always dial `https://<address>`, so to register
from a `gobl.dev` node against a local lookup you need a
domain-shaped hostname (e.g. `lookup.local` via `/etc/hosts`) and a
TLS-terminating proxy in front of the HTTP port with a locally
trusted certificate (e.g. Caddy or mkcert + nginx). The
countersigned envelope lands in your node's `inbox/` directory.
End-to-end behaviour without TLS plumbing is covered by the test
suites, which inject fetchers instead of dialing.

## CouchDB schema

One database (`gobl-lookup` by default). One document per
registered address with id `registration:<address>`:

```json
{
  "_id": "registration:alice.example",
  "address": "alice.example",
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
| `gobl.lookup verify <address>` | Recovery: re-derive verified status from the accepted-provider countersignatures already on the stored envelope and re-deliver. Normally automatic at registration. |
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
| `VERIFIERS`         | `--verifiers`        | —             | Comma-separated addresses of accepted verification providers (e.g. `didit.gobl.org`). |
| `LOG_JSON`          | `--json`             | `false`       | Emit structured JSON logs on stderr.                               |

Supply the CouchDB connection either as a single `COUCHDB_URL`
(handy for local dev, e.g. `http://admin:pass@localhost:5984`) or via
the split `COUCHDB_*` parts (the cluster convention, so the password
arrives from a secret independently of the host).

## Operations

- **Re-registration vs renewal**: re-submitting the unchanged party
  document (same digest) is a renewal — it keeps the current
  `verifier` and `verified_at`, stamping a fresh 90-day
  countersignature. Submitting **changed** party data drops the
  `verifier` and clears `verified_at`; verifying again requires
  another `gobl.lookup verify <address>` call. Audit trail lives in
  CouchDB revisions.
- **Delivery failures**: the inbox handler responds `202` once the
  record is persisted; delivery to the sender's `/inbox` happens
  asynchronously. Failures land on `Record.LastDeliveryError`;
  re-running `gobl.lookup verify` retries.
- **Sender eligibility**: registrations are only accepted from
  addresses that serve a verifiable `GET /who` identity of their
  own. Receive-only accounts (whose `/who` returns `204`) cannot
  register — they can receive documents without any registration.

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
