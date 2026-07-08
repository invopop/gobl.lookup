package repos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/uuid"

	"github.com/invopop/gobl.lookup/internal/domain/models"
)

// MemoryRegistrations is a thread-safe in-process registration store
// useful for tests and local dev. It preserves _rev-style optimistic
// concurrency so callers exercising the conflict path behave the same
// as against CouchDB.
type MemoryRegistrations struct {
	mu      sync.Mutex
	records map[string]*models.Registration
}

// NewMemoryRegistrations returns an empty in-memory registration store.
func NewMemoryRegistrations() *MemoryRegistrations {
	return &MemoryRegistrations{records: make(map[string]*models.Registration)}
}

// Put creates or updates the record, returning the new revision.
func (m *MemoryRegistrations) Put(_ context.Context, reg *models.Registration) (string, error) {
	if err := reg.Validate(); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, exists := m.records[reg.ID]
	if exists {
		if reg.Rev != prev.Rev {
			return "", ErrConflict
		}
	} else if reg.Rev != "" {
		return "", ErrConflict
	}
	reg.Rev = newRev()
	clone := *reg
	m.records[reg.ID] = &clone
	return reg.Rev, nil
}

// Get returns the record for an address or ErrNotFound.
func (m *MemoryRegistrations) Get(_ context.Context, address net.Address) (*models.Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[models.RegistrationDocID(address)]
	if !ok {
		return nil, ErrNotFound
	}
	clone := *r
	return &clone, nil
}

// GetByUUID returns the record whose IncomingEnvelopeUUID matches, or
// ErrNotFound.
func (m *MemoryRegistrations) GetByUUID(_ context.Context, id uuid.UUID) (*models.Registration, error) {
	target := id.String()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.records {
		if r.IncomingEnvelopeUUID.String() == target {
			clone := *r
			return &clone, nil
		}
	}
	return nil, ErrNotFound
}

// newRev generates an opaque revision string. Format mirrors
// CouchDB's "1-<hex>" shape just for parity; the leading integer
// is purely informational.
func newRev() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal; surface so tests notice.
		panic("repos: crypto/rand unavailable: " + err.Error())
	}
	return "1-" + hex.EncodeToString(b[:])
}
