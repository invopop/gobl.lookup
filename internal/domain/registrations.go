package domain

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/head"
	"github.com/invopop/gobl/org"
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

// Register processes a registration request: a delivery to this
// lookup's inbox of the subject's party envelope. The subject is the
// envelope's from address, confirmed by a signature for this lookup
// with the subject's current key, a new key, or both (spec §7.3). It
// resolves the subject's own GET /who to confirm the address serves an
// identity, updates the subject's key lineage, countersigns the
// envelope as the Authority, persists the record, and queues
// asynchronous delivery back to the subject's inbox. The persisted
// record is returned once stored; delivery happens in the background.
func (d *Registrations) Register(ctx context.Context, env *gobl.Envelope) (*models.Registration, error) {
	if err := env.Validate(); err != nil {
		d.log.Warn("inbox.rejected", "reason", "validation", "error", err.Error())
		return nil, ErrValidation.WithMessage("envelope failed validation: %s", err.Error())
	}

	keys, err := d.client.DeliveryKeys(ctx, env, d.identity.Address())
	if err != nil {
		if errors.Is(err, goblnet.ErrUnavailable) {
			d.log.Warn("inbox.rejected", "reason", "verify_unavailable", "error", err.Error())
			return nil, ErrUnavailable.WithMessage("could not reach the sender's key endpoint; retry later")
		}
		d.log.Warn("inbox.rejected", "reason", "verify_failed", "error", err.Error())
		return nil, ErrUnauthorized.WithMessage("envelope is not signed by its sender for this lookup: %s", err.Error())
	}
	sender, err := goblnet.ParseAddress(env.Head.From.Opaque())
	if err != nil {
		return nil, ErrValidation.WithCause(err)
	}
	if _, ok := env.Extract().(*org.Party); !ok {
		d.log.Warn("inbox.rejected", "reason", "not_a_party", "caller", string(sender))
		return nil, ErrValidation.WithMessage("registration envelope must contain an org.Party")
	}

	// Any signature claiming to be this lookup's must actually be one:
	// a renewal carries the previous countersignature, and a broken or
	// forged copy means the envelope is not what was endorsed.
	if err := d.verifyOwnSignatures(env); err != nil {
		d.log.Warn("inbox.rejected", "reason", "own_signature_invalid", "caller", string(sender), "error", err.Error())
		return nil, ErrUnauthorized.WithMessage("envelope carries an invalid countersignature claiming this lookup")
	}

	if err := d.checkWho(ctx, sender); err != nil {
		return nil, err
	}

	prev, err := d.store.Get(ctx, sender)
	switch {
	case errors.Is(err, repos.ErrNotFound):
		prev = nil
	case err != nil:
		return nil, ErrInternal.WithCause(err)
	}

	// Accepted verifications bind a subject key with cnf; one counts
	// only while that key is in the subject's lineage, which a rollover
	// extends and a lost key or a new holder of the address restarts.
	verifications, verr := d.acceptedVerifications(ctx, env, sender)
	if verr != nil {
		// A provider's key endpoint was unreachable: register
		// unverified rather than reject — the derivation re-runs on
		// the next renewal, or via the verify command.
		d.log.Warn("inbox.auto_verify_unavailable", "caller", string(sender), "error", verr.Error())
	}
	var lineage []*models.LineageKey
	if prev != nil {
		lineage = prev.Lineage
	}
	lineage, err = nextLineage(lineage, keys, verificationKeys(verifications), time.Now().UTC())
	if err != nil {
		d.log.Warn("inbox.rejected", "reason", "lineage", "caller", string(sender), "keys", len(keys))
		return nil, ErrValidation.WithMessage("%s", err.Error())
	}
	verifier := pickVerifier(verifications, lineage)

	// Stamp the discovery link to the public record before signing:
	// stamping replaces any copy from an earlier countersign round —
	// duplicate link keys make the envelope invalid. Header links are
	// unsigned (mutable post-signature) by design; the link is a
	// discovery hint, not part of the trust claim.
	d.stampDiscoveryLink(env)
	d.dropRequestSignatures(env, sender)

	// Countersign: adds the Authority signature for the subject's
	// address and current key, with any verifier claim and a 90-day
	// exp, and addresses the envelope back to the subject. UUID and
	// digest unchanged.
	if err := d.identity.CounterSign(env, CounterSignOptions{
		Subject:  sender,
		Key:      lineage[len(lineage)-1].JKT,
		Verifier: verifier,
	}); err != nil {
		d.log.Error("inbox.countersign_failed", "caller", string(sender), "error", err.Error())
		return nil, ErrInternal.WithCause(err)
	}

	// Persist before delivery so the record exists even if the
	// downstream POST fails.
	rec, err := d.upsert(ctx, prev, sender, env, verifier, lineage)
	if err != nil {
		d.log.Error("inbox.persist_failed", "caller", string(sender), "error", err.Error())
		return nil, ErrInternal.WithCause(err)
	}
	d.log.Info("inbox.accepted",
		"caller", string(sender),
		"envelope", env.Head.UUID.String(),
		"verifier", string(verifier),
		"lineage", len(lineage),
	)

	// Fire-and-forget delivery: the caller is acknowledged as soon
	// as we've persisted; the actual /inbox POST is done async. The
	// goroutine mutates its record (attempts/status), so hand it a copy
	// — the record returned to the caller stays immutable after return.
	recCopy := *rec
	go d.deliverAsync(sender, env, &recCopy)

	return rec, nil
}

// checkWho confirms the subject of a registration is a sending
// participant: GET /who on it must return a verified identity. A 204
// marks a receive-only account, which cannot register.
func (d *Registrations) checkWho(ctx context.Context, sender goblnet.Address) error {
	_, err := d.client.Who(ctx, sender)
	if err == nil {
		return nil
	}
	// A transient outage while resolving the sender's who must not
	// permanently reject the registration: senders stop retrying on
	// 4xx, so surface a retryable condition instead.
	if errors.Is(err, goblnet.ErrUnavailable) {
		d.log.Warn("inbox.rejected", "reason", "who_unavailable", "caller", string(sender), "error", err.Error())
		return ErrUnavailable.WithMessage("could not reach sender's public identity; retry later")
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
	return ErrForbidden.WithMessage("%s", msg)
}

// Verify marks an existing registration as identity-verified: it
// derives the verifier from the countersignatures already on the
// stored envelope — the most recent one from an accepted verification
// provider whose cnf names a key in the subject's lineage —
// re-countersigns with the `verifier` claim naming it, and delivers
// the result synchronously to the subject's inbox. The same derivation
// runs automatically on every registration, so this command exists
// for recovery: e.g. a provider added to the accepted list after its
// countersignature was received.
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
	key := rec.CurrentKey()
	if key == nil {
		return nil, ErrValidation.WithMessage("registration for %s has no key lineage; the subject must register again", addr)
	}
	env := rec.CountersignedEnvelope

	verifications, aerr := d.acceptedVerifications(ctx, env, addr)
	verifier := pickVerifier(verifications, rec.Lineage)
	if verifier == "" {
		if aerr != nil {
			return nil, ErrUnavailable.WithMessage("could not check verifier countersignatures: %s", aerr.Error())
		}
		return nil, ErrValidation.WithMessage("no countersignature from an accepted verifier for a key of %s on the registration envelope", addr)
	}

	// Restamp the discovery link (deduplicating any earlier rounds)
	// and stamp a fresh Authority signature carrying the verifier
	// claim onto the existing envelope.
	d.stampDiscoveryLink(env)
	if err := d.identity.CounterSign(env, CounterSignOptions{
		Subject:  addr,
		Key:      key.JKT,
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

// acceptedVerifications returns the valid countersignatures for
// subject on env from accepted verification providers. The crypto
// check matters: naming a verifier whose signature consumers would
// reject makes the registry attest to garbage. The error is non-nil
// only when a provider's key endpoint was unreachable
// (net.ErrUnavailable) — the caller decides whether that degrades or
// aborts.
func (d *Registrations) acceptedVerifications(ctx context.Context, env *gobl.Envelope, subject goblnet.Address) ([]*goblnet.Verification, error) {
	var (
		found       []*goblnet.Verification
		unavailable error
	)
	for v := range d.verifiers {
		ver, err := d.client.FindVerification(ctx, env, v, subject)
		if err != nil {
			if errors.Is(err, goblnet.ErrUnavailable) {
				unavailable = err
			}
			continue
		}
		found = append(found, ver)
	}
	return found, unavailable
}

// verificationKeys returns the cnf thumbprints of verifications.
func verificationKeys(vs []*goblnet.Verification) []string {
	keys := make([]string, 0, len(vs))
	for _, v := range vs {
		if v.Key != "" {
			keys = append(keys, v.Key)
		}
	}
	return keys
}

// pickVerifier returns the verifier of the most recent verification
// whose cnf names a key in lineage, or "".
func pickVerifier(vs []*goblnet.Verification, lineage []*models.LineageKey) goblnet.Address {
	var best *goblnet.Verification
	for _, v := range vs {
		if !inLineage(lineage, v.Key) {
			continue
		}
		if best == nil || v.IssuedAt.After(best.IssuedAt) {
			best = v
		}
	}
	if best == nil {
		return ""
	}
	return best.Verifier
}

func inLineage(lineage []*models.LineageKey, jkt string) bool {
	if jkt == "" {
		return false
	}
	for _, k := range lineage {
		if k.JKT == jkt {
			return true
		}
	}
	return false
}

// dropRequestSignatures removes the subject's signatures for this
// lookup: they confirmed the registration request and have served
// their purpose (spec §5).
func (d *Registrations) dropRequestSignatures(env *gobl.Envelope, sender goblnet.Address) {
	sigs := env.Signatures[:0]
	for _, sig := range env.Signatures {
		if p, err := head.SignedPayload(sig); err == nil {
			iss, ierr := goblnet.ParseAddress(p.Iss)
			aud, aerr := goblnet.ParseAddress(p.Aud)
			if ierr == nil && aerr == nil && iss == sender && aud == d.identity.Address() {
				continue
			}
		}
		sigs = append(sigs, sig)
	}
	env.Signatures = sigs
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

// stampDiscoveryLink replaces the lookup's discovery link on the
// envelope: every earlier round's copy is stripped first, since
// duplicate link keys fail envelope validation and links accumulate
// as the same envelope returns for renewals and verification.
func (d *Registrations) stampDiscoveryLink(env *gobl.Envelope) {
	if d.publicBaseURL == "" || env.Head == nil {
		return
	}
	links := make([]*head.Link, 0, len(env.Head.Links)+1)
	for _, l := range env.Head.Links {
		if l != nil && l.Category == head.LinkCategoryKeyVerification && l.Key == "lookup" {
			continue
		}
		links = append(links, l)
	}
	env.Head.Links = append(links, &head.Link{
		Category: head.LinkCategoryKeyVerification,
		Key:      "lookup",
		URL:      d.publicBaseURL + "/parties/" + env.Head.UUID.String(),
	})
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

// upsert writes the registration record for sender from the freshly
// countersigned envelope, building on prev (nil for a first
// registration, preserving the store's _rev token otherwise).
func (d *Registrations) upsert(ctx context.Context, prev *models.Registration, sender goblnet.Address, env *gobl.Envelope, verifier goblnet.Address, lineage []*models.LineageKey) (*models.Registration, error) {
	rec := prev
	prevVerifier := goblnet.Address("")
	if rec == nil {
		rec = models.NewRegistration(sender, env.Head.UUID)
	} else {
		prevVerifier = rec.Verifier
		rec.IncomingEnvelopeUUID = env.Head.UUID
		rec.ReceivedAt = time.Now().UTC()
		rec.DeliveryAttempts = 0
		rec.LastDeliveryError = ""
		rec.LastDeliveryAt = nil
	}
	rec.Verifier = verifier
	rec.Status = models.StatusCountersigned
	rec.CountersignedEnvelope = env
	rec.Lineage = lineage
	// The verification timestamp follows the verifier: dropped when
	// the verifier is dropped, kept across renewals with the same
	// verifier, and stamped fresh when a (new) provider verifies.
	switch {
	case verifier == "":
		rec.VerifiedAt = nil
	case rec.VerifiedAt == nil || verifier != prevVerifier:
		now := time.Now().UTC()
		rec.VerifiedAt = &now
	}
	if err := d.store.Put(ctx, rec); err != nil {
		return nil, err
	}
	return rec, nil
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
