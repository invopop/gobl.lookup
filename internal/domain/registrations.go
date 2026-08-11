package domain

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/head"
	goblnet "github.com/invopop/gobl/net"
	"github.com/invopop/gobl/uuid"

	"github.com/invopop/gobl.lookup/internal/domain/delivery"
	"github.com/invopop/gobl.lookup/internal/domain/models"
	"github.com/invopop/gobl.lookup/internal/domain/repos"
)

// deliveryTimeout bounds a single outbound POST to a subject's inbox.
const deliveryTimeout = 30 * time.Second

// endorsementTTL is the lifetime of every Authority countersignature
// this lookup issues, carried as the signed `exp` claim. Subjects
// renew by re-registering before it passes; an unchanged party
// renews with its current verifier.
const endorsementTTL = 90 * 24 * time.Hour

// Registrations manages the business logic for party registrations:
// verifying an incoming envelope, countersigning it as the
// Authority, persisting the record, and delivering the result
// back to the subject's own inbox.
type Registrations struct {
	store         RegistrationStore
	identity      *Identity
	client        *goblnet.Client
	sender        delivery.Sender
	verifiers     map[goblnet.Address]bool
	publicBaseURL string
	log           *slog.Logger
}

// newRegistrations instantiates the registrations domain service. The
// verifiers list is canonicalized into the set of provider addresses
// whose countersignatures the registry accepts.
func newRegistrations(store RegistrationStore, identity *Identity, client *goblnet.Client, sender delivery.Sender, verifiers []goblnet.Address, publicBaseURL string, log *slog.Logger) *Registrations {
	accepted := make(map[goblnet.Address]bool, len(verifiers))
	for _, v := range verifiers {
		if canon, err := goblnet.ParseAddress(string(v)); err == nil {
			accepted[canon] = true
		}
	}
	return &Registrations{
		store:         store,
		identity:      identity,
		client:        client,
		sender:        sender,
		verifiers:     accepted,
		publicBaseURL: publicBaseURL,
		log:           log,
	}
}

// Register processes a registration request: a signed envelope
// containing the subject's org.Party. It establishes the subject from
// the party document itself, resolves the subject's own GET /who to
// confirm the address serves a public identity, countersigns the
// envelope as the Authority, persists the record, and queues
// asynchronous delivery back to the subject's /inbox. The persisted
// record is returned once stored; delivery happens in the background.
func (d *Registrations) Register(ctx context.Context, env *gobl.Envelope) (*models.Registration, error) {
	if err := env.Validate(); err != nil {
		d.log.Warn("inbox.rejected", "reason", "validation", "error", err.Error())
		return nil, ErrValidation.WithMessage("envelope failed validation: %s", err.Error())
	}

	// Party envelopes are bearer documents (spec §8.3): the subject is
	// the address the party document itself declares, attested by a
	// valid self-signature — no audience binding, no significance to
	// signature order. The request token carries delivery intent and
	// the who eligibility check below gates who can register.
	sender, err := d.client.VerifyParty(ctx, env)
	if err != nil {
		switch {
		case errors.Is(err, goblnet.ErrUnavailable):
			d.log.Warn("inbox.rejected", "reason", "verify_unavailable", "error", err.Error())
			return nil, ErrUnavailable.WithMessage("could not reach the subject's key endpoint; retry later")
		case errors.Is(err, goblnet.ErrPartyMissing):
			d.log.Warn("inbox.rejected", "reason", "not_a_party", "error", err.Error())
			return nil, ErrValidation.WithMessage("registration envelope must contain an org.Party declaring a gobl: endpoint")
		}
		d.log.Warn("inbox.rejected", "reason", "verify_failed", "error", err.Error())
		return nil, ErrUnauthorized.WithMessage("signature verification failed")
	}

	// Any signature claiming to be this lookup's must actually be one:
	// a returned envelope (e.g. from a verification provider, §5.3)
	// carries the original countersignature, and a broken or forged
	// copy means the envelope is not what was endorsed.
	if err := d.verifyOwnSignatures(env); err != nil {
		d.log.Warn("inbox.rejected", "reason", "own_signature_invalid", "caller", string(sender), "error", err.Error())
		return nil, ErrUnauthorized.WithMessage("envelope carries an invalid countersignature claiming this lookup")
	}

	// The subject of a registration is a *sending* participant, so it
	// must serve a public identity of its own: GET /who on the sender
	// (which also re-fetches its published key) must return a verified
	// party. A 204 marks a receive-only account, which cannot register.
	if _, err := d.client.Who(ctx, sender); err != nil {
		// A transient outage while resolving the sender's who must not
		// permanently reject the registration: senders stop retrying
		// on 4xx, so surface a retryable condition instead.
		if errors.Is(err, goblnet.ErrUnavailable) {
			d.log.Warn("inbox.rejected", "reason", "who_unavailable", "caller", string(sender), "error", err.Error())
			return nil, ErrUnavailable.WithMessage("could not reach sender's public identity; retry later")
		}
		reason := "who_failed"
		msg := "could not resolve sender's public identity"
		switch {
		case errors.Is(err, goblnet.ErrNoContent):
			reason = "who_no_content"
			msg = "sender does not publish a public identity; senders must serve GET /who"
		case errors.Is(err, goblnet.ErrPending):
			reason = "who_pending"
			msg = "sender defers identity disclosure; senders must serve GET /who openly to register"
		}
		d.log.Warn("inbox.rejected", "reason", reason, "caller", string(sender), "error", err.Error())
		return nil, ErrForbidden.WithMessage("%s", msg)
	}

	// An unchanged party re-registering before its endorsement expires
	// is a renewal and keeps its current verifier; anything else
	// starts as registered only. Either way, a countersignature from
	// an accepted verification provider on the incoming envelope wins:
	// it attests to exactly this digest, so the registration is
	// verified from the start (auto-verify — the manual verify command
	// only re-triggers this same derivation).
	verifier, renewal := d.renewalVerifier(ctx, sender, env)
	if av, err := d.acceptedVerifier(ctx, env); av != "" {
		verifier = av
	} else if err != nil {
		// A provider's key endpoint was unreachable: register
		// unverified rather than reject — the derivation re-runs on
		// the next renewal, or via the verify command.
		d.log.Warn("inbox.auto_verify_unavailable", "caller", string(sender), "error", err.Error())
	}

	// Countersign: adds Authority signature with iss=lookup,
	// aud=sender, any preserved verifier claim, and a 90-day exp.
	// UUID + digest unchanged.
	if err := d.identity.CounterSign(env, CounterSignOptions{
		Subject:  sender,
		Verifier: verifier,
	}); err != nil {
		d.log.Error("inbox.countersign_failed", "caller", string(sender), "error", err.Error())
		return nil, ErrInternal.WithCause(err)
	}

	// Stamp a discovery link to the public record. Header links are
	// unsigned (mutable post-signature) by design; the link is a
	// discovery hint, not part of the trust claim.
	if d.publicBaseURL != "" {
		env.Head.Links = append(env.Head.Links, &head.Link{
			Category: head.LinkCategoryKeyVerification,
			Key:      "lookup",
			URL:      d.publicBaseURL + "/parties/" + env.Head.UUID.String(),
		})
	}

	// Persist before delivery so the record exists even if the
	// downstream POST fails.
	rec, err := d.upsert(ctx, sender, env, verifier, renewal)
	if err != nil {
		d.log.Error("inbox.persist_failed", "caller", string(sender), "error", err.Error())
		return nil, ErrInternal.WithCause(err)
	}
	d.log.Info("inbox.accepted",
		"caller", string(sender),
		"envelope", env.Head.UUID.String(),
		"verifier", string(verifier),
		"renewal", renewal,
	)

	// Fire-and-forget delivery: the caller is acknowledged as soon
	// as we've persisted; the actual /inbox POST is done async. The
	// goroutine mutates its record (attempts/status), so hand it a copy
	// — the record returned to the caller stays immutable after return.
	recCopy := *rec
	go d.deliverAsync(sender, env, &recCopy)

	return rec, nil
}

// Verify marks an existing registration as identity-verified: it
// derives the verifier from the countersignatures already on the
// stored envelope — the most recent one from an accepted verification
// provider — re-countersigns with the `verifier` claim naming it, and
// delivers the result synchronously to the subject's inbox. The same
// derivation runs automatically when a registration arrives carrying
// a provider countersignature, so this command exists for recovery:
// e.g. a provider added to the accepted list after its
// countersignature was received. The registry names itself only when
// it is on its own accepted list.
func (d *Registrations) Verify(ctx context.Context, addr goblnet.Address) (*models.Registration, error) {
	rec, err := d.store.Get(ctx, addr)
	if errors.Is(err, repos.ErrNotFound) {
		return nil, ErrNotFound.WithMessage("no registration for %s", addr)
	}
	if err != nil {
		return nil, ErrInternal.WithCause(err)
	}
	if rec.CountersignedEnvelope == nil {
		return nil, ErrValidation.WithMessage("registration for %s has no countersigned envelope", addr)
	}
	env := rec.CountersignedEnvelope

	verifier, aerr := d.acceptedVerifier(ctx, env)
	if verifier == "" {
		if aerr != nil {
			return nil, ErrUnavailable.WithMessage("could not check verifier countersignatures: %s", aerr.Error())
		}
		return nil, ErrValidation.WithMessage("no countersignature from an accepted verifier on the registration envelope for %s", addr)
	}

	// Stamp a fresh Authority signature carrying the verifier claim
	// onto the existing envelope.
	if err := d.identity.CounterSign(env, CounterSignOptions{
		Subject:  addr,
		Verifier: verifier,
	}); err != nil {
		return nil, ErrInternal.WithCause(err)
	}
	rec.Verifier = verifier
	now := time.Now().UTC()
	rec.VerifiedAt = &now
	rec.Status = models.StatusCountersigned
	// Count the attempt up front (as the async path does) so a failure is
	// still reflected in DeliveryAttempts.
	rec.DeliveryAttempts++
	rec.LastDeliveryAt = &now

	sendCtx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()
	if err := d.sender.Send(sendCtx, addr, env); err != nil {
		rec.Status = models.StatusFailed
		rec.LastDeliveryError = err.Error()
		_ = d.store.Put(ctx, rec)
		return nil, ErrInternal.WithCause(fmt.Errorf("deliver verified envelope: %w", err))
	}
	rec.Status = models.StatusDelivered
	rec.LastDeliveryError = ""
	if err := d.store.Put(ctx, rec); err != nil {
		return nil, ErrInternal.WithCause(err)
	}
	d.log.Info("verified registration",
		"address", string(addr),
		"envelope", env.Head.UUID.String(),
		"verifier", string(verifier),
	)
	return rec, nil
}

// acceptedVerifier returns the address behind the most recent
// unexpired countersignature on env whose signer is an accepted
// verification provider and whose signature verifies against the
// provider's published key, or "". The crypto check matters here:
// naming a verifier whose signature consumers would reject makes the
// registry attest to garbage. Latest-iat wins when several providers
// have countersigned. The error is non-nil only when a candidate's
// key endpoint was unreachable (net.ErrUnavailable) — the caller
// decides whether that degrades or aborts.
func (d *Registrations) acceptedVerifier(ctx context.Context, env *gobl.Envelope) (goblnet.Address, error) {
	var (
		best        goblnet.Address
		bestIat     int64 = -1
		unavailable error
	)
	now := time.Now().UTC().Unix()
	for _, sig := range env.Signatures {
		p, err := head.SignedPayload(sig)
		if err != nil {
			continue
		}
		issuer, err := goblnet.ParseAddress(p.Iss)
		if err != nil || !d.verifiers[issuer] {
			continue
		}
		if p.ExpiresAt != 0 && now >= p.ExpiresAt {
			continue
		}
		if p.IssuedAt <= bestIat {
			continue
		}
		pub, err := d.client.FetchKey(ctx, issuer, sig.KeyID())
		if err != nil {
			if errors.Is(err, goblnet.ErrUnavailable) {
				unavailable = err
			}
			continue
		}
		if err := env.Head.Verify(sig, pub); err != nil {
			continue
		}
		best, bestIat = issuer, p.IssuedAt
	}
	if best == "" && unavailable != nil {
		return "", unavailable
	}
	return best, nil
}

// verifyOwnSignatures checks every signature claiming this lookup's
// address against its own published keys. Returns an error when one
// claims an unknown key or fails verification; envelopes without any
// such signature (a first registration) pass untouched.
func (d *Registrations) verifyOwnSignatures(env *gobl.Envelope) error {
	for _, sig := range env.Signatures {
		p, err := head.SignedPayload(sig)
		if err != nil {
			continue
		}
		iss, err := goblnet.ParseAddress(p.Iss)
		if err != nil || iss != d.identity.Address() {
			continue
		}
		pub := d.identity.FindKey(sig.KeyID())
		if pub == nil {
			return fmt.Errorf("signature claims this lookup with unknown key %q", sig.KeyID())
		}
		if err := env.Head.Verify(sig, pub); err != nil {
			return fmt.Errorf("signature claiming this lookup does not verify: %w", err)
		}
	}
	return nil
}

// Find resolves a public lookup key — either an envelope UUID or a
// GOBL Net address — to its registration record. The path syntax is
// overloaded deliberately: operators can deep-link by UUID (immutable
// reference from the head.Link) or by human-readable address.
func (d *Registrations) Find(ctx context.Context, key string) (*models.Registration, error) {
	if id, err := uuid.Parse(key); err == nil {
		return d.found(d.store.GetByUUID(ctx, id))
	}
	addr, err := goblnet.ParseAddress(key)
	if err != nil {
		return nil, ErrNotFound
	}
	return d.found(d.store.Get(ctx, addr))
}

// found maps a repository lookup result onto domain errors.
func (d *Registrations) found(rec *models.Registration, err error) (*models.Registration, error) {
	switch {
	case errors.Is(err, repos.ErrNotFound):
		return nil, ErrNotFound
	case err != nil:
		return nil, ErrInternal.WithCause(err)
	}
	return rec, nil
}

// renewalVerifier resolves the verifier claim for a registration's
// countersignature. An existing record whose countersigned envelope
// has the same digest as the incoming one is renewing an unchanged
// party and keeps its current verifier; any other case starts as
// registered only (no verifier).
func (d *Registrations) renewalVerifier(ctx context.Context, sender goblnet.Address, env *gobl.Envelope) (goblnet.Address, bool) {
	prev, err := d.store.Get(ctx, sender)
	if err != nil || prev.CountersignedEnvelope == nil || !sameDigest(prev.CountersignedEnvelope, env) {
		return "", false
	}
	return prev.Verifier, true
}

// sameDigest reports whether both envelopes carry the same document
// digest.
func sameDigest(a, b *gobl.Envelope) bool {
	if a == nil || b == nil || a.Head == nil || b.Head == nil {
		return false
	}
	da, db := a.Head.Digest, b.Head.Digest
	return da != nil && db != nil && da.Algorithm == db.Algorithm && da.Value == db.Value
}

// upsert reads any existing record for sender (preserving the store's
// _rev token for optimistic concurrency), then writes the new state
// with the freshly countersigned envelope. A renewal keeps the
// record's verification timestamp; a re-registration with changed
// party data clears it — prior KYC no longer applies.
func (d *Registrations) upsert(ctx context.Context, sender goblnet.Address, env *gobl.Envelope, verifier goblnet.Address, renewal bool) (*models.Registration, error) {
	prev, err := d.store.Get(ctx, sender)
	switch {
	case errors.Is(err, repos.ErrNotFound):
		r := models.NewRegistration(sender, env.Head.UUID)
		r.Verifier = verifier
		if verifier != "" {
			now := time.Now().UTC()
			r.VerifiedAt = &now
		}
		r.Status = models.StatusCountersigned
		r.CountersignedEnvelope = env
		if err := d.store.Put(ctx, r); err != nil {
			return nil, err
		}
		return r, nil
	case err != nil:
		return nil, err
	}
	prevVerifier := prev.Verifier
	prev.IncomingEnvelopeUUID = env.Head.UUID
	prev.ReceivedAt = time.Now().UTC()
	prev.Verifier = verifier
	prev.Status = models.StatusCountersigned
	prev.CountersignedEnvelope = env
	prev.DeliveryAttempts = 0
	prev.LastDeliveryError = ""
	prev.LastDeliveryAt = nil
	// The verification timestamp follows the verifier: dropped when
	// the verifier is dropped, kept across renewals with the same
	// verifier, and stamped fresh when a (new) provider verifies.
	switch {
	case verifier == "":
		prev.VerifiedAt = nil
	case prev.VerifiedAt == nil || verifier != prevVerifier:
		now := time.Now().UTC()
		prev.VerifiedAt = &now
	}
	if err := d.store.Put(ctx, prev); err != nil {
		return nil, err
	}
	return prev, nil
}

// deliverAsync POSTs the countersigned envelope to the sender's own
// /inbox and records the outcome. The protocol is asynchronous; the
// original caller is acknowledged as soon as the record is persisted.
func (d *Registrations) deliverAsync(sender goblnet.Address, env *gobl.Envelope, rec *models.Registration) {
	ctx, cancel := context.WithTimeout(context.Background(), deliveryTimeout)
	defer cancel()
	rec.DeliveryAttempts++
	now := time.Now().UTC()
	rec.LastDeliveryAt = &now
	if err := d.sender.Send(ctx, sender, env); err != nil {
		rec.Status = models.StatusFailed
		rec.LastDeliveryError = err.Error()
		d.log.Warn("inbox.delivery_failed",
			"caller", string(sender),
			"envelope", env.Head.UUID.String(),
			"attempts", rec.DeliveryAttempts,
			"error", err.Error(),
		)
	} else {
		rec.Status = models.StatusDelivered
		rec.LastDeliveryError = ""
		d.log.Info("inbox.delivered",
			"caller", string(sender),
			"envelope", env.Head.UUID.String(),
		)
	}
	if err := d.store.Put(ctx, rec); err != nil {
		d.log.Error("inbox.persist_post_delivery_failed",
			"caller", string(sender),
			"envelope", env.Head.UUID.String(),
			"error", err.Error(),
		)
	}
}
