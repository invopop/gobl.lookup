package domain

import (
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/head"
	"github.com/invopop/gobl/org"

	"github.com/invopop/gobl.lookup/internal/domain/models"
)

// ListingKey is the envelope header meta key in which a registration
// request sets the subject's listing: ListingPublic or ListingPrivate.
// Without it, a registration keeps its listing; a new one is private.
const ListingKey cbc.Key = "lookup-listing"

// Listing values.
const (
	ListingPublic  = "public"
	ListingPrivate = "private"
)

// takeListing reads and removes the listing from env's header meta.
// It returns nil when the request sets none.
func takeListing(env *gobl.Envelope) (*bool, error) {
	v, ok := env.Head.Meta[ListingKey]
	if !ok {
		return nil, nil
	}
	delete(env.Head.Meta, ListingKey)
	if len(env.Head.Meta) == 0 {
		env.Head.Meta = nil
	}
	switch v {
	case ListingPublic:
		return boolPtr(true), nil
	case ListingPrivate:
		return boolPtr(false), nil
	}
	return nil, ErrValidation.WithMessage("meta %s must be %q or %q", ListingKey, ListingPublic, ListingPrivate)
}

func boolPtr(b bool) *bool { return &b }

// PartyRecord returns the public view of rec served at /parties: the
// address, verifier and registration dates, and for a public listing
// the party's name and tax ID. It returns nil when rec has no
// countersigned envelope yet.
func (d *Registrations) PartyRecord(rec *models.Registration) *models.PartyRecord {
	env := rec.CountersignedEnvelope
	if env == nil {
		return nil
	}
	out := &models.PartyRecord{
		Address:    rec.Address,
		Verifier:   rec.Verifier,
		VerifiedAt: rec.VerifiedAt,
		Public:     rec.Public,
	}
	if p := d.countersignature(env); p != nil {
		out.RegisteredAt = unixTime(p.IssuedAt)
		out.RegisteredUntil = unixTime(p.ExpiresAt)
	}
	if rec.Public {
		if party, ok := env.Extract().(*org.Party); ok {
			out.Name = party.Name
			out.TaxID = party.TaxID
		}
	}
	return out
}

// countersignature returns the payload of the lookup's own
// countersignature on env, or nil.
func (d *Registrations) countersignature(env *gobl.Envelope) *head.SigningPayload {
	self := d.identity.Address().String()
	for _, sig := range env.Signatures {
		if p, err := head.SignedPayload(sig); err == nil && p.Iss == self {
			return p
		}
	}
	return nil
}

func unixTime(s int64) *time.Time {
	if s == 0 {
		return nil
	}
	t := time.Unix(s, 0).UTC()
	return &t
}
