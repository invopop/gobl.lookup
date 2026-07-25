package models

import (
	"errors"
	"fmt"
	"time"

	"github.com/invopop/couch"
	"github.com/invopop/gobl"
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

// Registration is the per-address registration document persisted in
// CouchDB. The CouchDB document ID is "registration:<address>" so
// re-registrations land as new revisions on the same row. It embeds
// couch.Model for the _id/_rev + created_at/updated_at handling.
type Registration struct {
	couch.Model
	Address               net.Address    `json:"address"`
	Verifier              net.Address    `json:"verifier,omitempty"`
	Status                Status         `json:"status"`
	IncomingEnvelopeUUID  uuid.UUID      `json:"incoming_envelope_uuid"`
	ReceivedAt            time.Time      `json:"received_at"`
	CountersignedEnvelope *gobl.Envelope `json:"envelope,omitempty"`
	DeliveryAttempts      int            `json:"delivery_attempts,omitempty"`
	LastDeliveryError     string         `json:"last_delivery_error,omitempty"`
	LastDeliveryAt        *time.Time     `json:"last_delivery_at,omitempty"`
	VerifiedAt            *time.Time     `json:"verified_at,omitempty"`
}

// RegistrationDocID returns the CouchDB document ID for a given address.
func RegistrationDocID(addr net.Address) string {
	return "registration:" + string(addr)
}

// NewRegistration builds a fresh Registration for a freshly received
// envelope. The caller fills in Status / CountersignedEnvelope as the
// processing pipeline advances.
func NewRegistration(addr net.Address, envUUID uuid.UUID) *Registration {
	r := &Registration{
		Address:              addr,
		Status:               StatusReceived,
		IncomingEnvelopeUUID: envUUID,
		ReceivedAt:           time.Now().UTC(),
	}
	r.ID = RegistrationDocID(addr) // promoted from couch.Model
	return r
}

// Validate reports whether the record is internally consistent
// before it is written. Used by both the CouchDB store and tests
// to guard against malformed updates.
func (r *Registration) Validate() error {
	if r == nil {
		return errors.New("models: nil registration")
	}
	if r.Address == "" {
		return errors.New("models: registration address is required")
	}
	if r.ID == "" {
		return errors.New("models: registration _id is required")
	}
	if expected := RegistrationDocID(r.Address); r.ID != expected {
		return fmt.Errorf("models: registration _id %q does not match address %q", r.ID, expected)
	}
	if r.Status == "" {
		return errors.New("models: registration status is required")
	}
	return nil
}
