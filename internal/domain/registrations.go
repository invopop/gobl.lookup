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
	"github.com/invopop/gobl/org"
	"github.com/invopop/gobl/uuid"

	"github.com/invopop/gobl.lookup/internal/domain/delivery"
	"github.com/invopop/gobl.lookup/internal/domain/models"
	"github.com/invopop/gobl.lookup/internal/domain/repos"
)

// deliveryTimeout bounds a single outbound POST to a subject's inbox.
const deliveryTimeout = 30 * time.Second

// Registrations manages the business logic for party registrations:
// verifying an incoming envelope, countersigning it with the
// Authority scope, persisting the record, and delivering the result
// back to the subject's own inbox.
type Registrations struct {
	store         RegistrationStore
	identity      *Identity
	client        *goblnet.Client
	sender        delivery.Sender
	publicBaseURL string
	log           *slog.Logger
}

// newRegistrations instantiates the registrations domain service.
func newRegistrations(store RegistrationStore, identity *Identity, client *goblnet.Client, sender delivery.Sender, publicBaseURL string, log *slog.Logger) *Registrations {
	return &Registrations{
		store:         store,
		identity:      identity,
		client:        client,
		sender:        sender,
		publicBaseURL: publicBaseURL,
		log:           log,
	}
}

// Register processes a registration request: a signed envelope
// containing the sender's org.Party. It verifies the signature and
// audience, applies the allow-list, countersigns the envelope with
// head.ScopeRegistered, persists the record, and queues asynchronous
// delivery back to the sender's /inbox. The persisted record is
// returned once stored; delivery happens in the background.
func (d *Registrations) Register(ctx context.Context, env *gobl.Envelope) (*models.Registration, error) {
	if err := env.Validate(); err != nil {
		d.log.Warn("inbox.rejected", "reason", "validation", "error", err.Error())
		return nil, ErrValidation.WithMessage("envelope failed validation: %s", err.Error())
	}

	sender, err := d.client.VerifyEnvelope(ctx, env, "")
	if err != nil {
		d.log.Warn("inbox.rejected", "reason", "verify_failed", "error", err.Error())
		return nil, ErrUnauthorized.WithMessage("signature verification failed")
	}

	// Replay protection: signed aud MUST equal this lookup.
	p, perr := head.SignedPayload(env.Signatures[0])
	if perr != nil {
		d.log.Warn("inbox.rejected", "reason", "verify_failed", "caller", string(sender), "error", perr.Error())
		return nil, ErrUnauthorized.WithMessage("could not read signed payload")
	}
	if p.Aud == "" {
		d.log.Warn("inbox.rejected", "reason", "aud_missing", "caller", string(sender))
		return nil, ErrUnauthorized.WithMessage("envelope must carry an aud equal to this lookup")
	}
	if p.Aud != d.identity.URI() {
		d.log.Warn("inbox.rejected", "reason", "aud_mismatch", "caller", string(sender), "aud", string(p.Aud))
		return nil, ErrUnauthorized.WithMessage("envelope audience does not match this lookup")
	}
	if !d.identity.Allowed(sender) {
		d.log.Warn("inbox.rejected", "reason", "not_allowed", "caller", string(sender))
		return nil, ErrForbidden.WithMessage("sender not accepted")
	}

	// Registration entry must carry an org.Party — that's the
	// document we're attesting to.
	if _, ok := env.Extract().(*org.Party); !ok {
		d.log.Warn("inbox.rejected", "reason", "not_a_party", "caller", string(sender))
		return nil, ErrValidation.WithMessage("registration envelope must contain an org.Party document")
	}

	// Countersign: adds Authority signature with iss=lookup,
	// aud=sender, scope=registered. UUID + digest unchanged.
	if err := d.identity.CounterSign(env, CounterSignOptions{
		Subject: sender,
		Scope:   head.ScopeRegistered,
	}); err != nil {
		d.log.Error("inbox.countersign_failed", "caller", string(sender), "error", err.Error())
		return nil, ErrInternal.WithCause(err)
	}

	// Stamp a discovery link to the public record. Header links are
	// unsigned (mutable post-signature) by design; the link is a
	// discovery hint, not part of the trust claim.
	if d.publicBaseURL != "" {
		env.Head.Links = append(env.Head.Links, &head.Link{
			Category: "authority",
			Key:      "lookup",
			URL:      d.publicBaseURL + "/parties/" + env.Head.UUID.String(),
		})
	}

	// Persist before delivery so the record exists even if the
	// downstream POST fails.
	rec, err := d.upsert(ctx, sender, env)
	if err != nil {
		d.log.Error("inbox.persist_failed", "caller", string(sender), "error", err.Error())
		return nil, ErrInternal.WithCause(err)
	}
	d.log.Info("inbox.accepted",
		"caller", string(sender),
		"envelope", env.Head.UUID.String(),
		"scope", string(head.ScopeRegistered),
	)

	// Fire-and-forget delivery: the caller is acknowledged as soon
	// as we've persisted; the actual /inbox POST is done async.
	go d.deliverAsync(sender, env, rec)

	return rec, nil
}

// Verify bumps an existing registration's scope to head.ScopeVerified
// after out-of-band KYC, re-countersigns the stored envelope, and
// delivers it synchronously to the subject's inbox.
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

	// Stamp a fresh Authority signature with the verified scope onto
	// the existing envelope.
	if err := d.identity.CounterSign(env, CounterSignOptions{
		Subject: addr,
		Scope:   head.ScopeVerified,
	}); err != nil {
		return nil, ErrInternal.WithCause(err)
	}
	rec.Scope = head.ScopeVerified
	now := time.Now().UTC()
	rec.VerifiedAt = &now
	rec.Status = models.StatusCountersigned

	if err := d.sender.Send(ctx, addr, env); err != nil {
		rec.Status = models.StatusFailed
		rec.LastDeliveryError = err.Error()
		rec.LastDeliveryAt = &now
		_, _ = d.store.Put(ctx, rec)
		return nil, ErrInternal.WithCause(fmt.Errorf("deliver verified envelope: %w", err))
	}
	rec.Status = models.StatusDelivered
	rec.LastDeliveryError = ""
	rec.LastDeliveryAt = &now
	rec.DeliveryAttempts++
	if _, err := d.store.Put(ctx, rec); err != nil {
		return nil, ErrInternal.WithCause(err)
	}
	d.log.Info("verified registration",
		"address", string(addr),
		"envelope", env.Head.UUID.String(),
		"scope", string(head.ScopeVerified),
	)
	return rec, nil
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

// upsert reads any existing record for sender (preserving the store's
// _rev token for optimistic concurrency), then writes the new state
// with the freshly countersigned envelope. Re-registration drops
// scope back to "registered" — if the party data has changed, prior
// KYC no longer applies.
func (d *Registrations) upsert(ctx context.Context, sender goblnet.Address, env *gobl.Envelope) (*models.Registration, error) {
	prev, err := d.store.Get(ctx, sender)
	switch {
	case errors.Is(err, repos.ErrNotFound):
		r := models.NewRegistration(sender, env.Head.UUID)
		r.Scope = head.ScopeRegistered
		r.Status = models.StatusCountersigned
		r.CountersignedEnvelope = env
		if _, err := d.store.Put(ctx, r); err != nil {
			return nil, err
		}
		return r, nil
	case err != nil:
		return nil, err
	}
	prev.IncomingEnvelopeUUID = env.Head.UUID
	prev.ReceivedAt = time.Now().UTC()
	prev.Scope = head.ScopeRegistered
	prev.Status = models.StatusCountersigned
	prev.CountersignedEnvelope = env
	prev.DeliveryAttempts = 0
	prev.LastDeliveryError = ""
	prev.LastDeliveryAt = nil
	prev.VerifiedAt = nil
	if _, err := d.store.Put(ctx, prev); err != nil {
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
	if _, err := d.store.Put(ctx, rec); err != nil {
		d.log.Error("inbox.persist_post_delivery_failed",
			"caller", string(sender),
			"envelope", env.Head.UUID.String(),
			"error", err.Error(),
		)
	}
}
