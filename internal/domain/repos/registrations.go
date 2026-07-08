package repos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	kivik "github.com/go-kivik/kivik/v4"
	_ "github.com/go-kivik/kivik/v4/couchdb" // register the couchdb driver
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/uuid"

	"github.com/invopop/gobl.lookup/internal/domain/models"
)

// Registrations is a registration store backed by a single CouchDB
// database. Document IDs follow registration:<address>; the by-UUID
// lookup uses a `parties` design document whose view emits the
// envelope UUID as a secondary key.
type Registrations struct {
	db *kivik.DB
}

const (
	designDocID = "_design/parties"
	viewByUUID  = "by_uuid"
)

// NewRegistrations opens (and creates if needed) the named database
// on the provided kivik client, ensures the design document exists,
// and returns a ready-to-use store.
func NewRegistrations(ctx context.Context, client *kivik.Client, database string) (*Registrations, error) {
	if client == nil {
		return nil, errors.New("repos: kivik client is required")
	}
	if database == "" {
		return nil, errors.New("repos: database name is required")
	}
	exists, err := client.DBExists(ctx, database)
	if err != nil {
		return nil, fmt.Errorf("repos: couchdb DBExists: %w", err)
	}
	if !exists {
		if err := client.CreateDB(ctx, database); err != nil {
			return nil, fmt.Errorf("repos: couchdb CreateDB %q: %w", database, err)
		}
	}
	r := &Registrations{db: client.DB(database)}
	if err := r.db.Err(); err != nil {
		return nil, fmt.Errorf("repos: couchdb DB %q: %w", database, err)
	}
	if err := r.ensureDesignDoc(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// Close releases the underlying CouchDB connection.
func (r *Registrations) Close() error {
	if r.db == nil {
		return nil
	}
	return r.db.Close()
}

// designDocBody is the JSON for the parties design document.
var designDocBody = map[string]any{
	"_id":      designDocID,
	"language": "javascript",
	"views": map[string]any{
		viewByUUID: map[string]any{
			"map": `function(doc) {
				if (doc._id.indexOf("registration:") === 0 && doc.incoming_envelope_uuid) {
					emit(doc.incoming_envelope_uuid, null);
				}
			}`,
		},
	},
}

func (r *Registrations) ensureDesignDoc(ctx context.Context) error {
	row := r.db.Get(ctx, designDocID)
	var existing map[string]json.RawMessage
	err := row.ScanDoc(&existing)
	switch {
	case err == nil:
		// Already present. We don't attempt to upgrade the body in v1;
		// operators rotate by deleting the design doc.
		return nil
	case kivik.HTTPStatus(err) == http.StatusNotFound:
		// fall through to create.
	default:
		return fmt.Errorf("repos: couchdb read design doc: %w", err)
	}
	if _, err := r.db.Put(ctx, designDocID, designDocBody); err != nil {
		return fmt.Errorf("repos: couchdb create design doc: %w", err)
	}
	return nil
}

// Put creates or updates the record, returning the new revision. On
// ErrConflict the caller should re-Get and retry.
func (r *Registrations) Put(ctx context.Context, reg *models.Registration) (string, error) {
	if err := reg.Validate(); err != nil {
		return "", err
	}
	rev, err := r.db.Put(ctx, reg.ID, reg)
	if err != nil {
		if kivik.HTTPStatus(err) == http.StatusConflict {
			return "", ErrConflict
		}
		return "", fmt.Errorf("repos: couchdb put: %w", err)
	}
	reg.Rev = rev
	return rev, nil
}

// Get returns the record for an address or ErrNotFound.
func (r *Registrations) Get(ctx context.Context, address net.Address) (*models.Registration, error) {
	row := r.db.Get(ctx, models.RegistrationDocID(address))
	reg := new(models.Registration)
	if err := row.ScanDoc(reg); err != nil {
		if kivik.HTTPStatus(err) == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repos: couchdb get: %w", err)
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
