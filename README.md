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
> accepted-provider list (`--verifiers` / `VERIFIERS`), auto-verify
> on envelopes carrying a provider countersignature, and the
> `gobl.lookup verify` recovery command. The provider (verifier)
> side is the open piece — see the gap list at the end of this
> section.

Verification upgrades a *registered* identity to *verified* by
adding two things to the party envelope: a countersignature from a
KYC/KYB provider ("verifier" — any provider operating its own GOBL
Net address, e.g. `verify.example.com`), and a fresh registry
countersignature carrying the `verifier` claim that points at it.
The supplier drives the flow, the provider performs and charges for
the checks, and the registry records and names the result — every
hop is a plain GOBL Net inbox delivery.

1. **Register.** The supplier envelops its `org.Party` and signs it
   with its own key (`iss=<supplier>`, `aud=<registry>`), then
   POSTs it to the registry's `/inbox` — see
   [How registration works](#how-registration-works).
2. **Registered.** The registry verifies the envelope, countersigns
   it (no `verifier` claim yet — a *registered* identity), and
   delivers the result back to the supplier's inbox.
3. **Send to a provider.** The supplier delivers that registered
   envelope — its own signature plus the registry's
   countersignature — to its chosen provider's GOBL Net inbox
   (`aud=<verifier>`). The registration countersignature tells the
   provider the registry will accept its work, and the envelope
   itself pins verification to an exact `uuid` + `dig`: the checks
   and the eventual signature cannot drift apart.
4. **Email initiation.** The provider contacts the party through an
   address published in the party's own `emails` to start the
   process. Only someone reachable at the party's published mailbox
   can proceed, so third parties cannot run verification in a
   subject's name.
5. **KYB.** The representative completes the provider's usual
   process on the provider's own pages: contact details, payment,
   document/registry/UBO checks, AML screening. Payment is
   deliberately part of the KYC surface — cardholder data is itself
   a fraud signal — and keeps verification revenue entirely on the
   provider's side: the registry stays free.
6. **Countersign and return.** On success the provider countersigns
   the envelope (`iss=<verifier>`, `aud=<subject>`, `exp` a year or
   more — spec §5.3) and POSTs it to the registry's standard
   `/inbox` with its own request token. To the inbox this is an
   ordinary renewal: same digest, first signature still the
   subject's, one extra countersignature aboard. Failed or
   abandoned processes simply never produce a countersignature.
7. **Auto-verify.** The renewal carries a valid countersignature
   from a provider on the accepted list, so the registry
   re-countersigns with `verifier=<provider>` automatically — the
   same act as `gobl.lookup verify`, without an operator. The
   stored record gains `verifier` + `verified_at`.
8. **Deliver.** The registry delivers the updated envelope to the
   supplier's inbox, the standard delivery path.
9. **Publish.** The supplier stores the envelope and publishes it
   at its `/who`. It now carries two operative countersignatures
   with independent lifetimes: the registry's, naming the verifier
   (renewed on the ~90-day registration cycle), and the provider's
   own (a year or more). Earlier registry countersignatures from
   before verification may remain aboard — signatures are
   append-only — and receivers simply prefer the endorsement with
   the confirmed verifier. Only once published do receivers see the
   verified status.

Renewal interplay is unchanged: re-registering the identical party
document keeps the verifier claim; changed party data drops it and
the party goes through verification again (the provider's own
countersignature attests to the *checked* data, not to future
edits).

**Implementation gaps** (in rough order):

- The provider side itself: a reference verifier service that
  receives envelopes on its inbox, runs the email-initiated checks,
  and returns the countersigned envelope — first target, a dummy
  KYB provider for the sandbox environment.
- Publishing the accepted-provider list: today it is server
  configuration (`VERIFIERS`) and suppliers learn provider
  addresses out of band; the registry should expose the list with
  each provider's policy, pricing, and countersignature lifetime.
- A `head.Link` on the registration delivery pointing the subject
  at the accepted providers, so every registered party discovers
  the upgrade path.

## Architecture

The code follows a conventional layered layout:

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
(the mechanism container platforms use to inject config and
secrets); the equivalent flags override the environment for local
use.

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
| `VERIFIERS`         | `--verifiers`        | —             | Comma-separated addresses of accepted verification providers (e.g. `verify.example.com`). |
| `LOG_JSON`          | `--json`             | `false`       | Emit structured JSON logs on stderr.                               |

Supply the CouchDB connection either as a single `COUCHDB_URL`
(handy for local dev, e.g. `http://admin:pass@localhost:5984`) or via
the split `COUCHDB_*` parts (convenient under Kubernetes-style
deployments, so the password arrives from a secret independently of
the host).

## Live and sandbox deployments

The registry runs as two independent instances of this same
service:

| Instance | Address | Purpose |
|----------|---------|---------|
| Live     | `lookup.gobl.org`         | The network's default registration authority (`net.Authorities`). |
| Sandbox  | `lookup.sandbox.gobl.org` | Registration authority for the sandbox environment (`net.SandboxAuthorities`). |

There is no sandbox mode in the code: each instance is just a
deployment with its own identity (`CONFIG_DIR`), its own CouchDB
database (`COUCHDB_DATABASE`), and — the part that actually differs
— its own accepted verification providers (`VERIFIERS`). The
sandbox lists relaxed providers (e.g. a dummy KYB service that
approves test identities), so sandbox registrations flow through
exactly the live code path while carrying endorsements only sandbox
verifiers would issue. GOBL Net clients keep the environments apart
by construction: the live and sandbox trust lists are disjoint, and
sandbox clients opt in with `net.WithSandbox()` — a live verifier
never accepts a sandbox endorsement.

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

In a container deployment, mount the identity (`private.jwk` + `party.json` +
`keys/`) into `CONFIG_DIR` and inject the `COUCHDB_*` values (password
from a secret) as environment variables — see [Configuration](#configuration).

## License

See [LICENSE](LICENSE).
