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
// request (a bearer request token, spec §5.5) and returns
// the verified requester address. The token's audience must be this
// lookup and its freshness window must include the current time.
func (d *Identity) VerifyRequest(ctx context.Context, header string) (goblnet.Address, error) {
	return d.client.VerifyAuthorization(ctx, header, d.Address())
}

// PartyEnvelope returns the JSON of the lookup's party envelope for
// requester, served at GET /.well-known/gobl/who: from the lookup to
// the requester, signed for it (spec §5.1). The unsigned envelope is
// built once per process; each response gets its own signature.
func (d *Identity) PartyEnvelope(requester goblnet.Address) ([]byte, error) {
	d.partyOnce.Do(func() {
		env, err := gobl.Envelop(d.model.Party)
		if err != nil {
			d.partyErr = fmt.Errorf("identity: envelop party: %w", err)
			return
		}
		d.partyData, d.partyErr = json.Marshal(env)
	})
	if d.partyErr != nil {
		return nil, d.partyErr
	}
	env := new(gobl.Envelope)
	if err := json.Unmarshal(d.partyData, env); err != nil {
		return nil, fmt.Errorf("identity: copy party envelope: %w", err)
	}
	if err := goblnet.Sign(env, d.model.PrivateKey, d.Address(), requester); err != nil {
		return nil, fmt.Errorf("identity: sign party: %w", err)
	}
	return json.Marshal(env)
}

// CounterSignOptions configure a CounterSign call.
type CounterSignOptions struct {
	// Subject is the address of the party whose envelope is being
	// countersigned; copied into the signed `aud` field so the
	// resulting signature is bound to that specific subject.
	Subject goblnet.Address
	// Key is the thumbprint of the subject key the registration binds,
	// carried as the signed `cnf` claim (spec §7.3).
	Key string
	// Verifier names the participant that performed identity
	// verification (KYC/KYB) of the subject, carried as the signed
	// `verifier` claim. Empty asserts registration only.
	Verifier goblnet.Address
}

// CounterSign adds a fresh Authority countersignature to env, valid
// for endorsementTTL (carried as the signed `exp` claim), and addresses
// env from this lookup to the subject, which the countersignature
// confirms. The envelope's UUID and Digest are unchanged.
func (d *Identity) CounterSign(env *gobl.Envelope, opts CounterSignOptions) error {
	if env == nil || env.Head == nil {
		return errors.New("identity: cannot countersign a nil envelope")
	}
	// Supersede earlier rounds: the fresh countersignature replaces
	// any of this lookup's own (spec §5.3) — a lingering older one
	// could assert a verifier that has since been revoked. Other
	// parties' signatures are never touched.
	sigs := make([]*dsig.Signature, 0, len(env.Signatures)+1)
	for _, sig := range env.Signatures {
		if p, err := head.SignedPayload(sig); err == nil {
			if iss, ierr := goblnet.ParseAddress(p.Iss); ierr == nil && iss == d.Address() {
				continue
			}
		}
		sigs = append(sigs, sig)
	}
	env.Signatures = sigs
	if opts.Key == "" {
		return errors.New("identity: cannot countersign without a subject key")
	}
	signOpts := []head.SignOption{
		head.WithExpiration(time.Now().Add(endorsementTTL)),
		head.WithConfirmation(opts.Key),
	}
	if opts.Verifier != "" {
		signOpts = append(signOpts, head.WithVerifier(opts.Verifier.String()))
	}
	return goblnet.Sign(env, d.model.PrivateKey, d.Address(), opts.Subject, signOpts...)
}
