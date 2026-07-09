package repos

import (
	"context"
	"errors"
	"fmt"

	kivik "github.com/go-kivik/kivik/v4"
	"github.com/invopop/couch"
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/uuid"

	"github.com/invopop/gobl.lookup/internal/domain/models"
)

// Registrations is a registration store backed by a CouchDB database
// through the couch library. There is one database (the couch client's
// prefix); document IDs follow registration:<address>, and the by-UUID
// lookup uses a `parties` design document whose view emits the envelope
// UUID as a secondary key.
type Registrations struct {
	db *kivik.DB
}

const (
	designName  = "parties"
	designDocID = "_design/parties"
	viewByUUID  = "by_uuid"
)

// NewRegistrations opens (creating if needed) the registrations database
// on the provided couch client, syncs the design document, and returns a
// ready-to-use store.
func NewRegistrations(ctx context.Context, client *couch.Client) (*Registrations, error) {
	if client == nil {
		return nil, errors.New("repos: couch client is required")
	}
	db := client.DB("") // single database, named by the client's prefix
	if err := client.Create(ctx, db); err != nil {
		return nil, fmt.Errorf("repos: create database: %w", err)
	}
	if err := client.SyncDesigns(ctx, db, []*couch.Design{partiesDesign()}); err != nil {
		return nil, fmt.Errorf("repos: sync designs: %w", err)
	}
	return &Registrations{db: db}, nil
}

// Close releases the underlying CouchDB connection.
func (r *Registrations) Close() error {
	if r.db == nil {
		return nil
	}
	return r.db.Close()
}

// partiesDesign builds the design document backing GetByUUID: it emits
// (incoming_envelope_uuid → null) for every registration record.
func partiesDesign() *couch.Design {
	d := couch.NewDesign(designName)
	d.SetView(viewByUUID, &couch.View{
		Map: `function(doc) {
			if (doc._id.indexOf("registration:") === 0 && doc.incoming_envelope_uuid) {
				emit(doc.incoming_envelope_uuid, null);
			}
		}`,
	})
	return d
}

// Put creates or updates the record. On a revision conflict it returns
// ErrConflict so the caller can re-Get and retry.
func (r *Registrations) Put(ctx context.Context, reg *models.Registration) error {
	if err := reg.Validate(); err != nil {
		return err
	}
	if err := couch.Store(ctx, r.db, reg); err != nil {
		if errors.Is(err, couch.ErrAlreadyExists) {
			return ErrConflict
		}
		return fmt.Errorf("repos: store registration: %w", err)
	}
	return nil
}

// Get returns the record for an address or ErrNotFound.
func (r *Registrations) Get(ctx context.Context, address net.Address) (*models.Registration, error) {
	reg := new(models.Registration)
	reg.ID = models.RegistrationDocID(address)
	if err := couch.Fetch(ctx, r.db, reg); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repos: fetch registration: %w", err)
	}
	return reg, nil
}

// GetByUUID returns the record whose IncomingEnvelopeUUID matches, or
// ErrNotFound. Backs the public /parties/<uuid> endpoint.
func (r *Registrations) GetByUUID(ctx context.Context, id uuid.UUID) (*models.Registration, error) {
	rows := r.db.Query(ctx, designDocID, viewByUUID, kivik.Params(map[string]any{
		"key":          id.String(),
		"include_docs": true,
		"limit":        1,
	}))
	defer rows.Close() //nolint:errcheck
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("repos: couchdb view: %w", err)
		}
		return nil, ErrNotFound
	}
	reg := new(models.Registration)
	if err := rows.ScanDoc(reg); err != nil {
		return nil, fmt.Errorf("repos: couchdb view scan: %w", err)
	}
	return reg, nil
}
