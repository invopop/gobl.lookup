// Package domain handles all the business logic for the lookup
// service: verifying and countersigning party registrations,
// persisting them, and delivering the Authority's countersignature
// back to each subject. Setup wires the repositories and domain
// services together and is the single object handed to the transport
// adapters in interfaces/.
package domain

import (
	"context"
	"log/slog"

	goblnet "github.com/invopop/gobl/net"
	"github.com/invopop/gobl/uuid"

	"github.com/invopop/gobl.lookup/internal/domain/delivery"
	"github.com/invopop/gobl.lookup/internal/domain/models"
)

// RegistrationStore is the persistence contract the registrations
// service depends on. repos.Registrations (CouchDB) and
// repos.MemoryRegistrations (tests) both satisfy it.
type RegistrationStore interface {
	// Put creates or updates the record, returning the new revision.
	Put(ctx context.Context, reg *models.Registration) (string, error)
	// Get returns the record for an address or repos.ErrNotFound.
	Get(ctx context.Context, address goblnet.Address) (*models.Registration, error)
	// GetByUUID returns the record whose IncomingEnvelopeUUID matches,
	// or repos.ErrNotFound.
	GetByUUID(ctx context.Context, id uuid.UUID) (*models.Registration, error)
}

// Deps bundles the constructed resources handed to New. The transport
// adapters never see these directly — they talk to the domain
// services exposed by Setup.
type Deps struct {
	// Identity is the lookup's loaded GOBL Net identity.
	Identity *models.Identity
	// Registrations persists registration records.
	Registrations RegistrationStore
	// Client verifies incoming envelopes (FetchKey + crypto).
	Client *goblnet.Client
	// Sender delivers the countersigned envelope to the subject.
	Sender delivery.Sender
	// PublicBaseURL is the canonical https URL clients use to fetch
	// this lookup (e.g. "https://lookup.gobl.org"); used to build the
	// head.Link to the public registration record. Empty omits it.
	PublicBaseURL string
	// Logger receives domain event logs. Defaults to slog.Default().
	Logger *slog.Logger
}

// Setup holds all the domain resources together.
type Setup struct {
	identity      *Identity
	registrations *Registrations
	publicBaseURL string
}

// New prepares the domain setup from its constructed dependencies.
func New(d Deps) *Setup {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	s := new(Setup)
	s.identity = newIdentity(d.Identity, d.Client, d.Logger)
	// Resolve the effective public base URL here (defaulting to
	// https://<domain>) so both the domain and callers observe the same
	// value — the empty case is not visible downstream.
	s.publicBaseURL = d.PublicBaseURL
	if s.publicBaseURL == "" {
		s.publicBaseURL = "https://" + string(s.identity.Address())
	}
	s.registrations = newRegistrations(d.Registrations, s.identity, d.Client, d.Sender, s.publicBaseURL, d.Logger)
	return s
}

// Identity returns the identity domain service.
func (s *Setup) Identity() *Identity { return s.identity }

// Registrations returns the registrations domain service.
func (s *Setup) Registrations() *Registrations { return s.registrations }

// PublicBaseURL returns the effective canonical URL used for discovery
// links — the configured value, or https://<domain> when unset.
func (s *Setup) PublicBaseURL() string { return s.publicBaseURL }
