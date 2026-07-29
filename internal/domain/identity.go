package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/dsig"
	"github.com/invopop/gobl/head"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.lookup/internal/domain/models"
)

// Identity is the domain service wrapping the lookup's loaded
// identity. It owns the signing behaviour (countersigning subject
// envelopes, signing the service's own party), backs the open GET
// /who lookup, and exposes the identity's published-key data to the
// transport layer.
type Identity struct {
	model  *models.Identity
	client *goblnet.Client
	log    *slog.Logger

	partyOnce sync.Once
	partyData []byte
	partyErr  error
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

// FindKey returns the published key with the given kid, or nil.
func (d *Identity) FindKey(kid string) *dsig.PublicKey { return d.model.FindKey(kid) }

// JWKS returns the published keys as an RFC 7517 JWK Set.
func (d *Identity) JWKS() ([]byte, error) { return d.model.JWKS() }

// PublicKeys returns every key the lookup has published.
func (d *Identity) PublicKeys() []*dsig.PublicKey { return d.model.PublicKeys }

// VerifyRequest verifies the Authorization header of an inbound who
// or inbox request (a bearer request token, spec §5.5) and returns
// the verified requester address. The token's audience must be this
// lookup and its freshness window must include the current time.
func (d *Identity) VerifyRequest(ctx context.Context, header string) (goblnet.Address, error) {
	return d.client.VerifyAuthorization(ctx, header, d.Address())
}

// PartyEnvelope returns the JSON of the lookup's party wrapped in a
// self-signed envelope (iss = the lookup's address, no aud), served
// at GET /.well-known/gobl/who. The response is a static document:
// it is signed once per process and cached.
func (d *Identity) PartyEnvelope() ([]byte, error) {
	d.partyOnce.Do(func() {
		env, err := gobl.Envelop(d.model.Party)
		if err != nil {
			d.partyErr = fmt.Errorf("identity: envelop party: %w", err)
			return
		}
		if err := env.Sign(d.model.PrivateKey, head.WithIssuer(d.Address().String())); err != nil {
			d.partyErr = fmt.Errorf("identity: sign party: %w", err)
			return
		}
		d.partyData, d.partyErr = json.Marshal(env)
	})
	return d.partyData, d.partyErr
}

// CounterSignOptions configure a CounterSign call.
type CounterSignOptions struct {
	// Subject is the address of the party whose envelope is being
	// countersigned; copied into the signed `aud` field so the
	// resulting signature is bound to that specific subject.
	Subject goblnet.Address
	// Verifier names the authority that performed identity
	// verification (KYC/KYB) of the subject, carried as the signed
	// `verifier` claim. The lookup names itself when it performed the
	// verification. Empty asserts registration only.
	Verifier goblnet.Address
}

// CounterSign adds a fresh Authority countersignature to env, valid
// for endorsementTTL (carried as the signed `exp` claim). The
// envelope's UUID and Digest are unchanged — only the Signatures
// slice grows.
func (d *Identity) CounterSign(env *gobl.Envelope, opts CounterSignOptions) error {
	if env == nil || env.Head == nil {
		return errors.New("identity: cannot countersign a nil envelope")
	}
	signOpts := []head.SignOption{
		head.WithIssuer(d.Address().String()),
		head.WithAudience(opts.Subject.String()),
		head.WithExpiration(time.Now().Add(endorsementTTL)),
	}
	if opts.Verifier != "" {
		signOpts = append(signOpts, head.WithVerifier(opts.Verifier.String()))
	}
	return env.Sign(d.model.PrivateKey, signOpts...)
}
