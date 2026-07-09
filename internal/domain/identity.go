package domain

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/dsig"
	"github.com/invopop/gobl/head"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.lookup/internal/domain/models"
)

// Identity is the domain service wrapping the lookup's loaded
// identity. It owns the signing behaviour (countersigning subject
// envelopes, signing the service's own party), backs the mutual /who
// exchange, and exposes the identity's published-key data to the
// transport layer.
type Identity struct {
	model  *models.Identity
	client *goblnet.Client
	log    *slog.Logger
}

// newIdentity wraps a loaded identity model.
func newIdentity(m *models.Identity, client *goblnet.Client, log *slog.Logger) *Identity {
	return &Identity{model: m, client: client, log: log}
}

// Model returns the underlying identity data.
func (d *Identity) Model() *models.Identity { return d.model }

// Address returns the lookup's GOBL Net address.
func (d *Identity) Address() goblnet.Address { return d.model.Address() }

// URI returns the gobl: URI form of the lookup's address.
func (d *Identity) URI() cbc.URI { return d.model.URI() }

// Allowed reports whether caller is permitted by the allow-list.
func (d *Identity) Allowed(caller goblnet.Address) bool { return d.model.Allowed(caller) }

// FindKey returns the published key with the given kid, or nil.
func (d *Identity) FindKey(kid string) *dsig.PublicKey { return d.model.FindKey(kid) }

// JWKS returns the published keys as an RFC 7517 JWK Set.
func (d *Identity) JWKS() ([]byte, error) { return d.model.JWKS() }

// PublicKeys returns every key the lookup has published.
func (d *Identity) PublicKeys() []*dsig.PublicKey { return d.model.PublicKeys }

// PartyEnvelope returns the lookup's party wrapped in a freshly
// signed envelope, suitable for serving at /.well-known/gobl/who.
// `aud` is the caller's address (the /who exchange is mutual; the
// response is bound to the caller).
func (d *Identity) PartyEnvelope(aud cbc.URI) (*gobl.Envelope, error) {
	env, err := gobl.Envelop(d.model.Party)
	if err != nil {
		return nil, fmt.Errorf("identity: envelop party: %w", err)
	}
	if err := env.Sign(d.model.PrivateKey, d.URI(), aud); err != nil {
		return nil, fmt.Errorf("identity: sign party: %w", err)
	}
	return env, nil
}

// Exchange backs the authenticated mutual party exchange (/who): it
// verifies the caller's signed envelope (which must be addressed to
// this lookup), applies the allow-list, and returns the lookup's own
// party wrapped in a fresh envelope bound to the caller.
func (d *Identity) Exchange(ctx context.Context, env *gobl.Envelope) (*gobl.Envelope, error) {
	caller, err := d.client.VerifyEnvelope(ctx, env, d.URI())
	if err != nil {
		d.log.Warn("who.rejected", "reason", "verify_failed", "error", err.Error())
		return nil, ErrUnauthorized.WithMessage("signature verification failed")
	}
	// Require an explicit aud match so the log carries the right
	// reason (mirrors the inbox tightening).
	p, err := head.SignedPayload(env.Signatures[0])
	if err != nil || p.Aud != d.URI() {
		d.log.Warn("who.rejected", "reason", "aud_mismatch", "caller", string(caller))
		return nil, ErrUnauthorized.WithMessage("envelope audience does not match this lookup")
	}
	if !d.Allowed(caller) {
		d.log.Warn("who.rejected", "reason", "not_allowed", "caller", string(caller))
		return nil, ErrForbidden.WithMessage("caller not accepted")
	}
	out, err := d.PartyEnvelope(caller.URI())
	if err != nil {
		d.log.Error("who.sign_failed", "caller", string(caller), "error", err.Error())
		return nil, ErrInternal.WithCause(err)
	}
	d.log.Info("who.exchange", "caller", string(caller))
	return out, nil
}

// CounterSignOptions configure a CounterSign call.
type CounterSignOptions struct {
	// Subject is the address of the party whose envelope is being
	// countersigned; copied into the signed `aud` field so the
	// resulting signature is bound to that specific subject.
	Subject goblnet.Address
	// Scope is the Authority's confidence assertion (typically
	// head.ScopeRegistered for an initial registration,
	// head.ScopeVerified after KYC). Empty leaves Scope unset.
	Scope cbc.Key
}

// CounterSign adds a fresh Authority countersignature to env. The
// envelope's UUID and Digest are unchanged — only the Signatures
// slice grows.
func (d *Identity) CounterSign(env *gobl.Envelope, opts CounterSignOptions) error {
	if env == nil || env.Head == nil {
		return errors.New("identity: cannot countersign a nil envelope")
	}
	signOpts := []head.SignOption{}
	if opts.Scope != "" {
		signOpts = append(signOpts, head.WithScope(opts.Scope))
	}
	return env.Sign(d.model.PrivateKey, d.URI(), opts.Subject.URI(), signOpts...)
}
