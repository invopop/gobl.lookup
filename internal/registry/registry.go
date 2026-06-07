// Package registry defines the persistence interface for
// registration records and a CouchDB-backed implementation. A
// registration is one row per registered GOBL Net address.
package registry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/uuid"
)

// Status represents where a registration record is in the
// processing pipeline.
type Status string

// Pipeline states.
const (
	// StatusReceived means the incoming envelope is persisted but
	// has not yet been countersigned.
	StatusReceived Status = "received"
	// StatusCountersigned means the Authority countersignature has
	// been stamped onto the envelope; delivery to the sender's
	// inbox has not yet succeeded.
	StatusCountersigned Status = "countersigned"
	// StatusDelivered means the countersigned envelope was
	// successfully POSTed to the sender's /inbox (202 received).
	StatusDelivered Status = "delivered"
	// StatusFailed means the delivery attempt(s) failed. The
	// record carries the last error; a retry can be triggered.
	StatusFailed Status = "failed"
)

// Record is the per-address registration document persisted in
// CouchDB. The CouchDB document ID is "registration:<address>" so
// re-registrations land as new revisions on the same row.
type Record struct {
	ID                    string         `json:"_id"`
	Rev                   string         `json:"_rev,omitempty"`
	Address               net.Address    `json:"address"`
	Scope                 cbc.Key        `json:"scope,omitempty"`
	Status                Status         `json:"status"`
	IncomingEnvelopeUUID  uuid.UUID      `json:"incoming_envelope_uuid"`
	ReceivedAt            time.Time      `json:"received_at"`
	CountersignedEnvelope *gobl.Envelope `json:"envelope,omitempty"`
	DeliveryAttempts      int            `json:"delivery_attempts,omitempty"`
	LastDeliveryError     string         `json:"last_delivery_error,omitempty"`
	LastDeliveryAt        *time.Time     `json:"last_delivery_at,omitempty"`
	VerifiedAt            *time.Time     `json:"verified_at,omitempty"`
}

// DocID returns the CouchDB document ID for a given address.
func DocID(addr net.Address) string {
	return "registration:" + string(addr)
}

// Errors returned by the registry interface.
var (
	// ErrNotFound means no record exists for the requested key.
	ErrNotFound = errors.New("registry: record not found")
	// ErrConflict means the underlying store rejected the update
	// because the supplied _rev is stale. Callers should re-Get
	// the record and retry.
	ErrConflict = errors.New("registry: revision conflict")
)

// Registrar is the persistence interface implemented by the
// CouchDB store (and by in-memory mocks in tests).
type Registrar interface {
	// Put creates or updates the record. The returned rev is the
	// new document revision. On ErrConflict the caller should
	// re-Get and try again.
	Put(ctx context.Context, r *Record) (rev string, err error)
	// Get returns the record for an address or ErrNotFound.
	Get(ctx context.Context, address net.Address) (*Record, error)
	// GetByUUID returns the record whose IncomingEnvelopeUUID
	// matches, or ErrNotFound. Used by the public /parties/<uuid>
	// endpoint.
	GetByUUID(ctx context.Context, id uuid.UUID) (*Record, error)
}

// NewRecord builds a fresh Record for a freshly received envelope.
// The caller fills in Status / CountersignedEnvelope as the
// processing pipeline advances.
func NewRecord(addr net.Address, envUUID uuid.UUID) *Record {
	return &Record{
		ID:                   DocID(addr),
		Address:              addr,
		Status:               StatusReceived,
		IncomingEnvelopeUUID: envUUID,
		ReceivedAt:           time.Now().UTC(),
	}
}

// Validate reports whether the record is internally consistent
// before it is written. Used by both the CouchDB store and tests
// to guard against malformed updates.
func (r *Record) Validate() error {
	if r == nil {
		return errors.New("registry: nil record")
	}
	if r.Address == "" {
		return errors.New("registry: record address is required")
	}
	if r.ID == "" {
		return errors.New("registry: record _id is required")
	}
	if expected := DocID(r.Address); r.ID != expected {
		return fmt.Errorf("registry: record _id %q does not match address %q", r.ID, expected)
	}
	if r.Status == "" {
		return errors.New("registry: record status is required")
	}
	return nil
}
