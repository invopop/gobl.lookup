package registry

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
)

// CouchStore is a Registrar backed by a single CouchDB database.
// Document IDs follow registration:<address>; the by-UUID lookup
// uses a `parties` design document whose view emits the envelope
// UUID as a secondary key.
type CouchStore struct {
	db *kivik.DB
}

// ViewDocByUUID is the view used by GetByUUID. The view emits
// (incoming_envelope_uuid → null) per registration record.
const (
	designDocID    = "_design/parties"
	viewByUUID     = "by_uuid"
	byUUIDFullName = "parties/by_uuid"
)

// NewCouchStore opens (and creates if needed) the named database
// on the provided kivik client, ensures the design document
// exists, and returns a ready-to-use store.
func NewCouchStore(ctx context.Context, client *kivik.Client, database string) (*CouchStore, error) {
	if client == nil {
		return nil, errors.New("registry: kivik client is required")
	}
	if database == "" {
		return nil, errors.New("registry: database name is required")
	}
	exists, err := client.DBExists(ctx, database)
	if err != nil {
		return nil, fmt.Errorf("registry: couchdb DBExists: %w", err)
	}
	if !exists {
		if err := client.CreateDB(ctx, database); err != nil {
			return nil, fmt.Errorf("registry: couchdb CreateDB %q: %w", database, err)
		}
	}
	s := &CouchStore{db: client.DB(database)}
	if err := s.db.Err(); err != nil {
		return nil, fmt.Errorf("registry: couchdb DB %q: %w", database, err)
	}
	if err := s.ensureDesignDoc(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Close releases the underlying CouchDB connection.
func (s *CouchStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
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

func (s *CouchStore) ensureDesignDoc(ctx context.Context) error {
	row := s.db.Get(ctx, designDocID)
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
		return fmt.Errorf("registry: couchdb read design doc: %w", err)
	}
	if _, err := s.db.Put(ctx, designDocID, designDocBody); err != nil {
		return fmt.Errorf("registry: couchdb create design doc: %w", err)
	}
	return nil
}

// Put implements Registrar.
func (s *CouchStore) Put(ctx context.Context, r *Record) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	rev, err := s.db.Put(ctx, r.ID, r)
	if err != nil {
		if kivik.HTTPStatus(err) == http.StatusConflict {
			return "", ErrConflict
		}
		return "", fmt.Errorf("registry: couchdb put: %w", err)
	}
	r.Rev = rev
	return rev, nil
}

// Get implements Registrar.
func (s *CouchStore) Get(ctx context.Context, address net.Address) (*Record, error) {
	row := s.db.Get(ctx, DocID(address))
	r := new(Record)
	if err := row.ScanDoc(r); err != nil {
		if kivik.HTTPStatus(err) == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("registry: couchdb get: %w", err)
	}
	return r, nil
}

// GetByUUID implements Registrar by querying the parties/by_uuid
// view. Returns ErrNotFound if no record carries that envelope
// UUID.
func (s *CouchStore) GetByUUID(ctx context.Context, id uuid.UUID) (*Record, error) {
	rows := s.db.Query(ctx, designDocID, viewByUUID, kivik.Params(map[string]any{
		"key":          id.String(),
		"include_docs": true,
		"limit":        1,
	}))
	defer rows.Close() //nolint:errcheck
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("registry: couchdb view: %w", err)
		}
		return nil, ErrNotFound
	}
	r := new(Record)
	if err := rows.ScanDoc(r); err != nil {
		return nil, fmt.Errorf("registry: couchdb view scan: %w", err)
	}
	return r, nil
}
